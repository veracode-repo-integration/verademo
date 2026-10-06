package com.veracode.verademo.commands;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

public class RemoveAccountCommand implements BlabberCommand {
	private static final Logger logger = LogManager.getLogger("VeraDemo:RemoveAccountCommand");

	private Connection connect;

	public RemoveAccountCommand(Connection connect, String username) {
		super();
		this.connect = connect;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.veracode.verademo.commands.Command#execute()
	 */
	@Override
	public void execute(String blabberUsername) {
		String sqlQuery = "DELETE FROM listeners WHERE blabber=? OR listener=?;";
		logger.info(sqlQuery);
		try {
			// Sanitize username for logging
			String safeUsername = URLEncoder.encode(blabberUsername, "UTF-8");

			// First query: DELETE FROM listeners
			try (PreparedStatement action = connect.prepareStatement(sqlQuery)) {
				action.setString(1, blabberUsername);
				action.setString(2, blabberUsername);
				action.execute();
			}

			// Second query: SELECT blab_name
			sqlQuery = "SELECT blab_name FROM users WHERE username = ?";
			logger.info("Executing query for user: " + safeUsername);
			String blabName;
			try (PreparedStatement selectStmt = connect.prepareStatement(sqlQuery)) {
				selectStmt.setString(1, blabberUsername);
				try (ResultSet result = selectStmt.executeQuery()) {
					result.next();
					blabName = result.getString(1);
				}
			}

			/* START EXAMPLE VULNERABILITY */
			String event = "Removed account for blabber " + blabName;
			String safeEvent = URLEncoder.encode(event, "UTF-8");
			sqlQuery = "INSERT INTO users_history (blabber, event) VALUES (?, ?)";
			logger.info("Inserting history for user: " + safeUsername + ", event: " + safeEvent);
			try (PreparedStatement insertStmt = connect.prepareStatement(sqlQuery)) {
				insertStmt.setString(1, blabberUsername);
				insertStmt.setString(2, event);
				insertStmt.execute();
			}

			sqlQuery = "DELETE FROM users WHERE username = ?";
			logger.info("Deleting user: " + safeUsername);
			try (PreparedStatement deleteStmt = connect.prepareStatement(sqlQuery)) {
				deleteStmt.setString(1, blabberUsername);
				deleteStmt.execute();
			}
			/* END EXAMPLE VULNERABILITY */

		} catch (SQLException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// UTF-8 is always supported, this should never happen
			e.printStackTrace();
		}
	}
}
