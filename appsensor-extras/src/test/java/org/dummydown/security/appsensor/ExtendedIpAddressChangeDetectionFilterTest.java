package org.dummydown.security.appsensor;

import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import junit.framework.TestCase;

import org.dummydown.security.appsensor.ExtendedIpAddressChangeDetectionFilter.ConcurrentMapSessionRemoteIPTrackingStore;
import org.dummydown.security.appsensor.ExtendedIpAddressChangeDetectionFilter.SessionRemoteIPTrackingStore;
import org.mockito.InOrder;
import org.mockito.Mockito;
import org.mockito.exceptions.verification.NoInteractionsWanted;

public class ExtendedIpAddressChangeDetectionFilterTest extends TestCase {

	public void testInit() throws Exception {
		ExtendedIpAddressChangeDetectionFilter extendedIpAddressChangeDetectionFilter = new ExtendedIpAddressChangeDetectionFilter();
		try {
			FilterConfig filterConfig = Mockito.mock(FilterConfig.class);
			Mockito.when(filterConfig.getInitParameter(ExtendedIpAddressChangeDetectionFilter.SESSION_IP_ADDRESS_ATTRIBUTE_NAME_PARAMETER)).thenReturn("originatingRemoteIpAddress");
		    extendedIpAddressChangeDetectionFilter.init(filterConfig);
		    assertTrue(ExtendedIpAddressChangeDetectionFilter.sessionRemoteIPTracker.getSessionRemoteIPTrackingStore() instanceof ExtendedIpAddressChangeDetectionFilter.SessionAttributeSessionRemoteIPTrackingStore);
		} finally {
			extendedIpAddressChangeDetectionFilter.destroy();
		}
		
		extendedIpAddressChangeDetectionFilter = new ExtendedIpAddressChangeDetectionFilter();
		try {
			FilterConfig filterConfig = Mockito.mock(FilterConfig.class);
			Mockito.when(filterConfig.getInitParameter(ExtendedIpAddressChangeDetectionFilter.SESSION_IP_ADDRESS_ATTRIBUTE_NAME_PARAMETER)).thenReturn(null);
		    extendedIpAddressChangeDetectionFilter.init(filterConfig);
		    assertTrue(ExtendedIpAddressChangeDetectionFilter.sessionRemoteIPTracker.getSessionRemoteIPTrackingStore() instanceof ExtendedIpAddressChangeDetectionFilter.ConcurrentMapSessionRemoteIPTrackingStore);
		} finally {
			extendedIpAddressChangeDetectionFilter.destroy();
		}
	}
	
	public void testMiserableTrackingConditions() throws Exception {
		ExtendedIpAddressChangeDetectionFilter extendedIpAddressChangeDetectionFilter = new ExtendedIpAddressChangeDetectionFilter();
		try {
			FilterConfig filterConfig = Mockito.mock(FilterConfig.class);
			FilterChain filterChain = Mockito.mock(FilterChain.class);
			ServletRequest req = Mockito.mock(HttpServletRequest.class);
			ServletResponse res = Mockito.mock(HttpServletResponse.class);
			Mockito.when(filterConfig.getInitParameter(ExtendedIpAddressChangeDetectionFilter.SESSION_IP_ADDRESS_ATTRIBUTE_NAME_PARAMETER)).thenReturn("originatingRemoteIpAddress");
		    extendedIpAddressChangeDetectionFilter.init(filterConfig);
		    extendedIpAddressChangeDetectionFilter.doFilter(req, res, filterChain);
		} finally {
			extendedIpAddressChangeDetectionFilter.destroy();
		}
	}
	
	public void testNewRequestTracking() throws Exception {
		ExtendedIpAddressChangeDetectionFilter extendedIpAddressChangeDetectionFilter = new ExtendedIpAddressChangeDetectionFilter();
		try {
			FilterChain filterChain = Mockito.mock(FilterChain.class);
			HttpServletRequest req = Mockito.mock(HttpServletRequest.class);
			ServletResponse res = Mockito.mock(HttpServletResponse.class);
			HttpSession session = Mockito.mock(HttpSession.class);
			SessionRemoteIPTrackingStore store = Mockito.mock(ConcurrentMapSessionRemoteIPTrackingStore.class);
			Mockito.when(req.getSession(false)).thenReturn(session);
			Mockito.when(req.getRemoteAddr()).thenReturn("74.125.225.67");
			Mockito.when(session.getId()).thenReturn("ID");
			Mockito.when(store.contains(session)).thenReturn(false);
			ExtendedIpAddressChangeDetectionFilter.sessionRemoteIPTracker = extendedIpAddressChangeDetectionFilter.new XForwardedForEagerSessionRemoteIPTracker(
					store, 
					null);
		    extendedIpAddressChangeDetectionFilter.doFilter(req, res, filterChain);
		    InOrder inOrder = inOrder(store);
		    inOrder.verify(store).contains(session);
		    inOrder.verify(store).put(session, "74.125.225.67");
		    try {
		    	verifyNoMoreInteractions(store);
		    } catch (NoInteractionsWanted e) {
		    	fail();
		    }
		} finally {
			extendedIpAddressChangeDetectionFilter.destroy();
		}
	}
	
	public void testValidIPRequestTracking() throws Exception {
		ExtendedIpAddressChangeDetectionFilter extendedIpAddressChangeDetectionFilter = new ExtendedIpAddressChangeDetectionFilter();
		try {
			FilterChain filterChain = Mockito.mock(FilterChain.class);
			HttpServletRequest req = Mockito.mock(HttpServletRequest.class);
			ServletResponse res = Mockito.mock(HttpServletResponse.class);
			HttpSession session = Mockito.mock(HttpSession.class);
			SessionRemoteIPTrackingStore store = Mockito.mock(ConcurrentMapSessionRemoteIPTrackingStore.class);
			Mockito.when(req.getSession(false)).thenReturn(session);
			Mockito.when(req.getRemoteAddr()).thenReturn("74.125.225.67");
			Mockito.when(session.getId()).thenReturn("ID");
			Mockito.when(store.contains(session)).thenReturn(false);
			ExtendedIpAddressChangeDetectionFilter.sessionRemoteIPTracker = extendedIpAddressChangeDetectionFilter.new XForwardedForEagerSessionRemoteIPTracker(
					store, 
					null);
		    extendedIpAddressChangeDetectionFilter.doFilter(req, res, filterChain);
		    InOrder inOrder = inOrder(store);
		    inOrder.verify(store).contains(session);
		    inOrder.verify(store).put(session, "74.125.225.67");
		    try {
		    	verifyNoMoreInteractions(store);
		    } catch (NoInteractionsWanted e) {
		    	fail();
		    }
		    Mockito.when(store.contains(session)).thenReturn(true);
		    Mockito.when(store.get(session)).thenReturn("74.125.225.67");
		    extendedIpAddressChangeDetectionFilter.doFilter(req, res, filterChain);
		    InOrder secondCallInOrder = inOrder(store);
		    secondCallInOrder.verify(store).contains(session);
		    secondCallInOrder.verify(store).get(session);
		} finally {
			extendedIpAddressChangeDetectionFilter.destroy();
		}
	}
	
	public void testInvalidIPRequestTracking() throws Exception {
		ExtendedIpAddressChangeDetectionFilter extendedIpAddressChangeDetectionFilter = new ExtendedIpAddressChangeDetectionFilter();
		try {
			FilterChain filterChain = Mockito.mock(FilterChain.class);
			HttpServletRequest req = Mockito.mock(HttpServletRequest.class);
			ServletResponse res = Mockito.mock(HttpServletResponse.class);
			HttpSession session = Mockito.mock(HttpSession.class);
			SessionRemoteIPTrackingStore store = Mockito.mock(ConcurrentMapSessionRemoteIPTrackingStore.class);
			Mockito.when(req.getSession(false)).thenReturn(session);
			Mockito.when(req.getRemoteAddr()).thenReturn("74.125.225.67");
			Mockito.when(session.getId()).thenReturn("ID");
			Mockito.when(store.contains(session)).thenReturn(false);
			ExtendedIpAddressChangeDetectionFilter.sessionRemoteIPTracker = spy(extendedIpAddressChangeDetectionFilter.new XForwardedForEagerSessionRemoteIPTracker(
					store, 
					null));
		    extendedIpAddressChangeDetectionFilter.doFilter(req, res, filterChain);
		    InOrder inOrder = inOrder(store);
		    inOrder.verify(store).contains(session);
		    inOrder.verify(store).put(session, "74.125.225.67");
		    try {
		    	verifyNoMoreInteractions(store);
		    } catch (NoInteractionsWanted e) {
		    	fail();
		    }
		    Mockito.when(store.contains(session)).thenReturn(true);
		    Mockito.when(req.getRemoteAddr()).thenReturn("74.125.225.68");
		    Mockito.when(store.get(session)).thenReturn("74.125.225.67");
			extendedIpAddressChangeDetectionFilter.doFilter(req, res, filterChain);
		    InOrder secondCallInOrder = inOrder(store, ExtendedIpAddressChangeDetectionFilter.sessionRemoteIPTracker);
		    secondCallInOrder.verify(store).contains(session);
		    secondCallInOrder.verify(store).get(session);
		    secondCallInOrder.verify(ExtendedIpAddressChangeDetectionFilter.sessionRemoteIPTracker).broadcastAppSensorException("ID", "74.125.225.67", "74.125.225.68");
		} finally {
			extendedIpAddressChangeDetectionFilter.destroy();
		}
	}
}
