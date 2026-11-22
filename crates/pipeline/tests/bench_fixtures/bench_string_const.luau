local function dispatch(needle)
	if needle == "service_players_get" then return 1 end
	if needle == "service_workspace_find" then return 2 end
	if needle == "command_kill_target" then return 3 end
	if needle == "command_teleport_to" then return 4 end
	if needle == "player_character_root" then return 5 end
	if needle == "gui_screen_notify" then return 6 end
	if needle == "remote_event_fire" then return 7 end
	if needle == "http_request_json" then return 8 end
	if needle == "data_store_update" then return 9 end
	if needle == "tween_service_play" then return 10 end
	if needle == "camera_subject_set" then return 11 end
	if needle == "sound_effect_emit" then return 12 end
	if needle == "part_anchor_toggle" then return 13 end
	if needle == "team_color_assign" then return 14 end
	if needle == "chat_message_send" then return 15 end
	if needle == "input_began_bind" then return 16 end
	return 0
end

local function work(n)
	local probes = { "chat_message_send", "unknown_key_value", "command_kill_target", "input_began_bind", "service_players_get" }
	local s = 0
	for i = 1, n do
		s = s + dispatch(probes[(i % 5) + 1])
	end
	return s
end

print(work(800))
