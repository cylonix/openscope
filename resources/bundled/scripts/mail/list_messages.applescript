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

on join_with(items_list, separator_text)
	set AppleScript's text item delimiters to separator_text
	set joined to items_list as text
	set AppleScript's text item delimiters to ""
	return joined
end join_with

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
set target_limit_text to {{limit}}
set unread_only_text to {{unread}}

set max_results to 20
try
	if target_limit_text is not "" then
		set max_results to (target_limit_text as integer)
	end if
end try
if max_results < 1 then set max_results to 1
if max_results > 100 then set max_results to 100

set unread_only to false
if unread_only_text is "true" then set unread_only to true

set target_mailbox to resolve_mailbox(target_mailbox_name)

tell application "Mail"
	set target_messages to messages of target_mailbox
end tell

set json_items to {}
set emitted_count to 0
repeat with target_message in target_messages
	tell application "Mail"
		set message_id to message id of target_message
		set message_subject to subject of target_message
		set message_sender to sender of target_message
		set message_date to date received of target_message
		set message_read_status to read status of target_message
	end tell
	if (not unread_only) or (message_read_status is false) then
		set date_text to message_date as text
		set unread_text to "false"
		if message_read_status is false then set unread_text to "true"
		set end of json_items to "{\"id\":\"" & json_escape(message_id) & "\",\"mailbox\":\"" & json_escape(target_mailbox_name) & "\",\"subject\":\"" & json_escape(message_subject) & "\",\"sender\":\"" & json_escape(message_sender) & "\",\"received_at\":\"" & json_escape(date_text) & "\",\"unread\":" & unread_text & "}"
		set emitted_count to emitted_count + 1
		if emitted_count ≥ max_results then exit repeat
	end if
end repeat

return "[" & join_with(json_items, ",") & "]"
