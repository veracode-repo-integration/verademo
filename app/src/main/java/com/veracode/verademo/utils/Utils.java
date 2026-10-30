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
		// Sanitize cookie name and value to prevent HTTP response splitting (CWE-113)
		String sanitizedName = sanitizeCookieValue(name);
		String sanitizedValue = sanitizeCookieValue(value);

		Cookie cookie = new Cookie(sanitizedName, sanitizedValue);
		// Set Secure attribute to prevent transmission over unencrypted connections (CWE-614)
		cookie.setSecure(true);
		cookie.setHttpOnly(true);

		response.addCookie(cookie);
		upgradeCookieSecurityForHttpsIfRequired(response);
	}

	private static String sanitizeCookieValue(String input) {
		if (input == null) {
			return "";
		}
		// Remove carriage return (\r) and line feed (\n) characters to prevent HTTP response splitting
		return input.replaceAll("[\r\n]", "");
	}

	public static String redirect(String destination) {
		if (isConnectionFromHttps()) {
			return "redirect:https://" + getVirtualHost() + "/" + destination;
		}

		return "redirect:" + destination;
	}
}
