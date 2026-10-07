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

		// CWE-117 fix: Sanitize host before logging
		try {
			String safeHost = URLEncoder.encode(host, "UTF-8");
			logger.info("Pinging: " + safeHost);
		} catch (UnsupportedEncodingException e) {
			logger.info("Pinging: [encoding error]");
		}

		// CWE-78 fix: Validate host to prevent command injection
		// Only allow alphanumeric characters, dots, and hyphens
		if (host == null || !host.matches("^[a-zA-Z0-9.-]+$")) {
			return "Invalid host format. Only alphanumeric characters, dots, and hyphens are allowed.";
		}

		try {
			proc = Runtime.getRuntime().exec(new String[] { "bash", "-c", "ping -c1 " + host });

			proc.waitFor(5, TimeUnit.SECONDS);
			InputStreamReader isr = new InputStreamReader(proc.getInputStream());
			// CWE-404 fix: Use try-with-resources to ensure BufferedReader is closed
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
		// CWE-78 fix: Validate fortuneFile to prevent command injection
		// Only allow alphanumeric characters and underscores
		if (fortuneFile == null || !fortuneFile.matches("^[a-zA-Z0-9_]+$")) {
			return "Invalid fortune file format. Only alphanumeric characters and underscores are allowed.";
		}

		String cmd = "/bin/fortune " + fortuneFile;

		String output = "";
		Process proc;
		try {
			proc = Runtime.getRuntime().exec(new String[] { "bash", "-c", cmd });

			proc.waitFor(5, TimeUnit.SECONDS);
			InputStreamReader isr = new InputStreamReader(proc.getInputStream());
			// CWE-404 fix: Use try-with-resources to ensure BufferedReader is closed
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
