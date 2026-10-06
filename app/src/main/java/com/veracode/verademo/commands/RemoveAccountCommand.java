package com.veracode.verademo.commands;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

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

			// First query: Delete from listeners
			try (PreparedStatement action = connect.prepareStatement(sqlQuery)) {
				action.setString(1, blabberUsername);
				action.setString(2, blabberUsername);
				action.execute();
			}

			// Second query: Get blab_name from users
			sqlQuery = "SELECT blab_name FROM users WHERE username = ?";
			logger.info(sqlQuery + " [username=" + safeUsername + "]");
			String blabName;
			try (PreparedStatement selectStatement = connect.prepareStatement(sqlQuery)) {
				selectStatement.setString(1, blabberUsername);
				try (ResultSet result = selectStatement.executeQuery()) {
					result.next();
					blabName = result.getString(1);
				}
			}

			/* START EXAMPLE VULNERABILITY - NOW FIXED */
			String event = "Removed account for blabber " + blabName;
			sqlQuery = "INSERT INTO users_history (blabber, event) VALUES (?, ?)";
			logger.info(sqlQuery + " [blabber=" + safeUsername + "]");
			try (PreparedStatement insertStatement = connect.prepareStatement(sqlQuery)) {
				insertStatement.setString(1, blabberUsername);
				insertStatement.setString(2, event);
				insertStatement.execute();
			}

			sqlQuery = "DELETE FROM users WHERE username = ?";
			logger.info(sqlQuery + " [username=" + safeUsername + "]");
			try (PreparedStatement deleteStatement = connect.prepareStatement(sqlQuery)) {
				deleteStatement.setString(1, blabberUsername);
				deleteStatement.execute();
			}
			/* END EXAMPLE VULNERABILITY - NOW FIXED */

		} catch (SQLException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
	}
}
