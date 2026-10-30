package com.veracode.verademo.controller;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.concurrent.TimeUnit;

import javax.servlet.ServletContext;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@Scope("request")
public class ToolsController {
	private static final Logger logger = LogManager.getLogger("VeraDemo:ToolsController");

	@Autowired
	ServletContext context;

	@RequestMapping(value = "/tools", method = RequestMethod.GET)
	public String tools() {
		return "tools";
	}

	@RequestMapping(value = "/tools", method = RequestMethod.POST)
	public String tools(@RequestParam(value = "host", required = false) String host, @RequestParam(value = "fortunefile", required = false) String fortuneFile, Model model) {
		model.addAttribute("ping", host != null ? ping(host) : "");

		if (fortuneFile == null) {
			fortuneFile = "literature";
		}
		model.addAttribute("fortunes", fortune(fortuneFile));

		return "tools";
	}

	private String ping(String host) {
		String output = "";
		Process proc;

		// Sanitize host for logging (CWE-117)
		try {
			String safeHost = URLEncoder.encode(host, "UTF-8");
			logger.info("Pinging: " + safeHost);
		} catch (UnsupportedEncodingException e) {
			logger.error("Error encoding host for logging", e);
		}

		// Validate and sanitize host input (CWE-78)
		if (host == null || !host.matches("^[a-zA-Z0-9.-]+$")) {
			logger.warn("Invalid host format");
			return "Invalid host format. Only alphanumeric characters, dots, and hyphens are allowed.";
		}

		try {
			/* START EXAMPLE VULNERABILITY */
			proc = Runtime.getRuntime().exec(new String[] { "ping", "-c", "1", host });
			/* END EXAMPLE VULNERABILITY */

			proc.waitFor(5, TimeUnit.SECONDS);
			InputStreamReader isr = new InputStreamReader(proc.getInputStream());
			// Use try-with-resources to ensure BufferedReader is closed (CWE-404)
			try (BufferedReader br = new BufferedReader(isr)) {
				String line;

				while ((line = br.readLine()) != null) {
					output += line + "\n";
				}
			}

			logger.info(proc.exitValue());
		} catch (IOException ex) {
			logger.error(ex);
		} catch (InterruptedException ex) {
			logger.error(ex);
		}

		return output;
	}

	private String fortune(String fortuneFile) {
		// Validate and sanitize fortuneFile input (CWE-78)
		if (fortuneFile == null || !fortuneFile.matches("^[a-zA-Z0-9_-]+$")) {
			logger.warn("Invalid fortune file format");
			return "Invalid fortune file format. Only alphanumeric characters, underscores, and hyphens are allowed.";
		}

		String output = "";
		Process proc;
		try {
			/* START EXAMPLE VULNERABILITY */
			proc = Runtime.getRuntime().exec(new String[] { "/bin/fortune", fortuneFile });
			/* END EXAMPLE VULNERABILITY */

			proc.waitFor(5, TimeUnit.SECONDS);
			InputStreamReader isr = new InputStreamReader(proc.getInputStream());
			// Use try-with-resources to ensure BufferedReader is closed (CWE-404)
			try (BufferedReader br = new BufferedReader(isr)) {
				String line;

				while ((line = br.readLine()) != null) {
					output += line + "\n";
				}
			}
		} catch (IOException ex) {
			logger.error(ex);
		} catch (InterruptedException ex) {
			logger.error(ex);
		}

		return output;
	}
}
