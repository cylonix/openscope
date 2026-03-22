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

set target_list_name to {{list}}
set target_limit_text to {{limit}}
set max_results to 20
try
	if target_limit_text is not "" then set max_results to (target_limit_text as integer)
end try
if max_results < 1 then set max_results to 1
if max_results > 100 then set max_results to 100

set json_items to {}
set emitted_count to 0

tell application "Reminders"
	set target_list to first list whose name is target_list_name
	repeat with target_reminder in every reminder of target_list
		set reminder_name to name of target_reminder as text
		set completed_text to "false"
		if completed of target_reminder is true then set completed_text to "true"
		set end of json_items to "{\"list\":\"" & json_escape(target_list_name) & "\",\"title\":\"" & json_escape(reminder_name) & "\",\"completed\":" & completed_text & "}"
		set emitted_count to emitted_count + 1
		if emitted_count ≥ max_results then exit repeat
	end repeat
end tell

return "[" & join_with(json_items, ",") & "]"
