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

set target_limit_text to {{limit}}
set max_results to 20
try
	if target_limit_text is not "" then set max_results to (target_limit_text as integer)
end try
if max_results < 1 then set max_results to 1
if max_results > 100 then set max_results to 100

set json_items to {}
set emitted_count to 0

tell application "Contacts"
	repeat with target_person in every person
		set first_name to first name of target_person as text
		set last_name to last name of target_person as text
		set full_name to name of target_person as text
		set end of json_items to "{\"name\":\"" & json_escape(full_name) & "\",\"first_name\":\"" & json_escape(first_name) & "\",\"last_name\":\"" & json_escape(last_name) & "\"}"
		set emitted_count to emitted_count + 1
		if emitted_count ≥ max_results then exit repeat
	end repeat
end tell

return "[" & join_with(json_items, ",") & "]"
