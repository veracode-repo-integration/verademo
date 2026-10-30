package com.veracode.verademo.utils;

import java.util.Collection;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;

public class Utils {
	private static boolean isConnectionFromHttps() {
		return System.getenv("CONNECTION_FROM_HTTPS") != null && System.getenv("CONNECTION_FROM_HTTPS").equals("1");
	}

	private static String getVirtualHost() {
		return System.getenv("VIRTUAL_HOST");
	}

	public static String getSessionUserName(HttpServletRequest request, HttpServletResponse response) {
		String username = (String) request.getSession().getAttribute("username");
		upgradeCookieSecurityForHttpsIfRequired(response);
		
		return username;
	}

	public static void setSessionUserName(HttpServletRequest request, HttpServletResponse response, String value) {
		request.getSession().setAttribute("username", value);
		upgradeCookieSecurityForHttpsIfRequired(response);
	}

	private static void upgradeCookieSecurityForHttpsIfRequired(HttpServletResponse response) {
		if (!isConnectionFromHttps()) {
			return;
		}

		Collection<String> headers = response.getHeaders(HttpHeaders.SET_COOKIE);
		boolean firstHeader = true;
		for (String header : headers) {
			// there can be multiple Set-Cookie attributes
			if (firstHeader) {
				response.setHeader(HttpHeaders.SET_COOKIE, String.format("%s; SameSite=None; Secure;", header));
				firstHeader = false;
				continue;
			}
			response.addHeader(HttpHeaders.SET_COOKIE, String.format("%s; SameSite=None; Secure;", header));
		}
	}

	public static void setUsernameCookie(HttpServletResponse response, String value) {
		setCookie(response, "username", value);
	}

	public static void setCookie(HttpServletResponse response, String name, String value) {
		// Sanitize cookie value to prevent CRLF injection (CWE-113)
		String sanitizedValue = sanitizeCookieValue(value);

		Cookie cookie = new Cookie(name, sanitizedValue);

		// Set Secure attribute for HTTPS connections (CWE-614)
		if (isConnectionFromHttps()) {
			cookie.setSecure(true);
		}

		response.addCookie(cookie);
		upgradeCookieSecurityForHttpsIfRequired(response);
	}

	/**
	 * Sanitizes cookie values by removing carriage return and line feed characters
	 * to prevent HTTP response splitting attacks.
	 */
	private static String sanitizeCookieValue(String value) {
		if (value == null) {
			return null;
		}
		// Remove CR (\r) and LF (\n) characters to prevent HTTP response splitting
		return value.replaceAll("[\r\n]", "");
	}

	public static String redirect(String destination) {
		if (isConnectionFromHttps()) {
			return "redirect:https://" + getVirtualHost() + "/" + destination;
		}

		return "redirect:" + destination;
	}
}
