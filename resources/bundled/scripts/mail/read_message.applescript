on replace_text(subject, search_string, replacement_string)
	set AppleScript's text item delimiters to search_string
	set parts to every text item of subject
	set AppleScript's text item delimiters to replacement_string
	set rebuilt to parts as text
	set AppleScript's text item delimiters to ""
	return rebuilt
end replace_text

on json_escape(value_text)
	set escaped to replace_text(value_text, "\\", "\\\\")
	set escaped to replace_text(escaped, "\"", "\\\"")
	set escaped to replace_text(escaped, return, "\\n")
	set escaped to replace_text(escaped, linefeed, "\\n")
	return escaped
end json_escape

on resolve_mailbox(target_mailbox_name)
	tell application "Mail"
		repeat with acc in every account
			repeat with mb in every mailbox of acc
				try
					set mailbox_name to name of mb
					if mailbox_name is target_mailbox_name then
						return contents of mb
					end if
					if target_mailbox_name is "Inbox" and mailbox_name is "INBOX" then
						return contents of mb
					end if
				end try
			end repeat
		end repeat

		repeat with mb in every mailbox
			try
				set mailbox_name to name of mb
				if mailbox_name is target_mailbox_name then
					return contents of mb
				end if
				if target_mailbox_name is "Inbox" and mailbox_name is "INBOX" then
					return contents of mb
				end if
			end try
		end repeat

		error "Mailbox not found: " & target_mailbox_name
	end tell
end resolve_mailbox

set target_mailbox_name to {{mailbox}}
set target_message_id to {{id}}

set target_mailbox to resolve_mailbox(target_mailbox_name)

tell application "Mail"
	set target_message to first message of target_mailbox whose message id is target_message_id
	set message_subject to subject of target_message
	set message_sender to sender of target_message
	set message_body to content of target_message
end tell

return "{\"id\":\"" & json_escape(target_message_id) & "\",\"mailbox\":\"" & json_escape(target_mailbox_name) & "\",\"subject\":\"" & json_escape(message_subject) & "\",\"sender\":\"" & json_escape(message_sender) & "\",\"body\":\"" & json_escape(message_body) & "\"}"
