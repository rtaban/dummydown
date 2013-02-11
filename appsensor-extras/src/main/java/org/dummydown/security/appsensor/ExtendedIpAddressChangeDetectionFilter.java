package org.dummydown.security.appsensor;

import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.owasp.appsensor.errors.AppSensorException;

/**
 * This filter extends the capabilities of the original OWASP Appsensor
 * {@link org.owasp.appsensor.filters.IpAddressChangeDetectionFilter} (although
 * it does not inherite from).
 * 
 * User of this filter can benefit the filter in real world environments where
 * both servlet container and the request originating client are behind forward
 * and reverse proxies. The filter replaces the remote IP address with the first
 * one present in X-Fowarded-For header.
 * 
 * User are allowed to store the remote IP address in the session rather than in
 * private local Map. This feature allows scaling of the solution: sessions can
 * be replicated over other node of cluster, therefore a private Map would not
 * scale.
 * 
 * Implementation's done with extensibility and maintainability in mind.
 * 
 * An example of configuration in web.xml would look like this:
 * 
 * <filter> 
 * 	   <filter-name>ExtendedIpAddressChangeDetectionFilter</filter-name>
 * 	   <filter-class>org.dummydown.security.appsensor.ExtendedIpAddressChangeDetectionFilter</filter-class>
 *     <init-param>
 *         <param-name>sessionIpAddressAttributeName</param-name>
 *         <param-value>originatingRemoteIpAddress</param-value>
 *     </init-param>
 *     <init-param>
 *         <param-name>appSensorEventCode</param-name>
 *         <param-value>SE7</param-value>
 *     </init-param>
 * </filter> 
 * 
 * <filter-mapping>
 * 	   <filter-name>ExtendedIpAddressChangeDetectionFilter</filter-name>
 * 	   <url-pattern>/*</url-pattern> 
 * </filter-mapping>
 * 
 */
public class ExtendedIpAddressChangeDetectionFilter implements Filter {

	protected static final String X_FORWARDED_FOR_HTTP_HEADER_NAME = "X-Forwarded-For";
	
	protected static final String SESSION_IP_ADDRESS_ATTRIBUTE_NAME_PARAMETER = "sessionIpAddressAttributeName";
	
	protected static final String APP_SENSOR_EVENT_CODE_PARAMETER = "appSensorEventCode";
	
	protected static SessionRemoteIPTracker sessionRemoteIPTracker = null;

	/**
	 * Default constructor.
	 */
	public ExtendedIpAddressChangeDetectionFilter() {
	}

	/**
	 * @see Filter#destroy()
	 */
	public void destroy() {
	}

	/**
	 * @see Filter#doFilter(ServletRequest, ServletResponse, FilterChain)
	 */
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		sessionRemoteIPTracker.track(request);
		chain.doFilter(req, res);
	}
	
	
	interface SessionRemoteIPTracker {
		void track(HttpServletRequest request);
		SessionRemoteIPTrackingStore getSessionRemoteIPTrackingStore();
		void broadcastAppSensorException(String sessionId, String originalIP, String suspectIP);
	}

	class XForwardedForEagerSessionRemoteIPTracker implements SessionRemoteIPTracker {

		private static final String DEFAULT_APP_SENSOR_CODE = "DDSE_7";
		private SessionRemoteIPTrackingStore sessionRemoteIPTrackingStore;
		
		private String appSensorEventCode;
		
		XForwardedForEagerSessionRemoteIPTracker(SessionRemoteIPTrackingStore sessionRemoteIPTrackingStore, String appSensorEventCode) {
			this.sessionRemoteIPTrackingStore = sessionRemoteIPTrackingStore;
			this.appSensorEventCode = appSensorEventCode != null ? appSensorEventCode : DEFAULT_APP_SENSOR_CODE;
		}
		
		public void track(HttpServletRequest request) {
			HttpSession session = request.getSession(false);
			String xForwardedForHeaderClientIP = null;
			Enumeration<String> xForwardedForHeaderEnumeration = request.getHeaders(X_FORWARDED_FOR_HTTP_HEADER_NAME);
			if (xForwardedForHeaderEnumeration != null) {
				List<String> xForwardedForHeaderEnumerationValues = Collections.list(xForwardedForHeaderEnumeration);
				if (xForwardedForHeaderEnumerationValues != null && xForwardedForHeaderEnumerationValues.size() > 0) {
					xForwardedForHeaderClientIP = xForwardedForHeaderEnumerationValues.get(0);
				}
			}
			String clientIP = xForwardedForHeaderClientIP != null ? xForwardedForHeaderClientIP : request.getRemoteAddr();
			if (trackingConditionsMet(session, clientIP)) {
				if (!sessionRemoteIPTrackingStore.contains(session)) {
					sessionRemoteIPTrackingStore.put(session, clientIP);
				} else {
					String existingClientIP = sessionRemoteIPTrackingStore.get(session);
					if (!clientIP.equals(existingClientIP)) {
						broadcastAppSensorException(session.getId(), existingClientIP, clientIP);
					}
				}
			}
		}
		
		public SessionRemoteIPTrackingStore getSessionRemoteIPTrackingStore() {
			return sessionRemoteIPTrackingStore;
		}
		
		public void broadcastAppSensorException(String sessionId, String originalIP, String suspectIP) {
			new AppSensorException(appSensorEventCode, "AppSensorUser Message " + appSensorEventCode,
					"Client IP Address for session has changed - original client IP [" + originalIP + "]"
							+ " / new client IP [" + suspectIP
							+ "] for session id [" + sessionId + "]");
		}
		
		private boolean trackingConditionsMet(HttpSession session, String remoteIP) {
			return sessionRemoteIPTrackingStore != null && session != null && session.getId() != null && remoteIP != null;
		}
	}
	
	interface SessionRemoteIPTrackingStore {
		void put(HttpSession session, String remoteIP);
		boolean contains(HttpSession session);
		String get(HttpSession session);
		
	}
	
	class ConcurrentMapSessionRemoteIPTrackingStore implements SessionRemoteIPTrackingStore {

		private ConcurrentMap<String, String> trackingMap = null;
		
		ConcurrentMapSessionRemoteIPTrackingStore(ConcurrentMap<String, String> trackingMap) {
			this.trackingMap = trackingMap;
		}

		public void put(HttpSession session, String clientIP) {
			trackingMap.putIfAbsent(session.getId(), clientIP);
		}

		public boolean contains(HttpSession session) {
			String sessionId = session.getId();
			return trackingMap.containsKey(sessionId);
		}

		public String get(HttpSession session) {
			return trackingMap.get(session.getId());
		}
	}
	
	class SessionAttributeSessionRemoteIPTrackingStore implements SessionRemoteIPTrackingStore {

		private String sessionAttributeName = null;
		
		SessionAttributeSessionRemoteIPTrackingStore(String sessionAttributeName) {
			this.sessionAttributeName = sessionAttributeName;
		}
		
		public void put(HttpSession session, String remoteIP) {
			session.setAttribute(sessionAttributeName, remoteIP);
		}

		public boolean contains(HttpSession session) {
			return session.getAttribute(sessionAttributeName) != null;
		}

		public String get(HttpSession session) {
			return (String) session.getAttribute(sessionAttributeName);
		}
		
	}

	/**
	 * @see Filter#init(FilterConfig)
	 */
	public void init(FilterConfig filterConfig) throws ServletException {
		SessionRemoteIPTrackingStore sessionRemoteIPTrackingStore = null;
		if (filterConfig.getInitParameter(SESSION_IP_ADDRESS_ATTRIBUTE_NAME_PARAMETER) != null) {
			sessionRemoteIPTrackingStore = new SessionAttributeSessionRemoteIPTrackingStore(filterConfig.getInitParameter(SESSION_IP_ADDRESS_ATTRIBUTE_NAME_PARAMETER));
        } else {
        	sessionRemoteIPTrackingStore = new ConcurrentMapSessionRemoteIPTrackingStore(new ConcurrentHashMap<String, String>());
        }
		ExtendedIpAddressChangeDetectionFilter.sessionRemoteIPTracker = new XForwardedForEagerSessionRemoteIPTracker(
				sessionRemoteIPTrackingStore, 
				filterConfig.getInitParameter(APP_SENSOR_EVENT_CODE_PARAMETER));
	}
}
