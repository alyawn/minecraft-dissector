
void proto_register_minecraft(void)
{
    module_t *module;

    if (proto_minecraft == -1)
    {
        static hf_register_info hf[] = {
            { &hf_mc_data,
                {"Data", "mc.data", FT_NONE, BASE_NONE, NULL, 0x0, "Packet Data", HFILL}
            },
            { &hf_mc_type,
              { "Type", "mc.type", FT_UINT8, BASE_HEX, VALS(packettypenames), 0x0, "Packet Type", HFILL }
            },
            { &hf_mc_server_name,
              {"Server Name", "mc.server_name", FT_STRING, BASE_NONE, NULL, 0x0, "Text", HFILL}
            },
            { &hf_mc_motd,
              {"MOTD", "mc.motd", FT_STRING, BASE_NONE, NULL, 0x0, "Text", HFILL}
            },
            { &hf_mc_username,
              {"Username", "mc.username", FT_STRING, BASE_NONE, NULL, 0x0, "Text", HFILL}
            },
            { &hf_mc_password,
              {"Password", "mc.password", FT_STRING, BASE_NONE, NULL, 0x0, "Text", HFILL}
            },
            { &hf_mc_serverid,
              {"Server ID", "mc.server_id", FT_STRING, BASE_NONE, NULL, 0x0, "Text", HFILL}
            },
            { &hf_mc_handshake_username,
              {"Handshake Username", "mc.handshake_username", FT_STRING, BASE_NONE, NULL, 0x0, "Text", HFILL}
            },
            { &hf_mc_chat,
              {"Chat", "mc.chat", FT_STRING, BASE_NONE, NULL, 0x0, "Text", HFILL}
            },
            { &hf_mc_time,
              {"Time", "mc.time", FT_INT64, BASE_DEC, NULL, 0x0, "Update Time", HFILL }
            },
            { &hf_mc_loaded,
              {"Loaded", "mc.loaded", FT_BOOLEAN, BASE_DEC, NULL, 0x0, "Loaded", HFILL }
            },
            { &hf_mc_double_coords,
              {"Coordinates", "mc.coords", FT_NONE, BASE_NONE, NULL, 0x0, "Coordinates", HFILL }
            },
            { &hf_mc_x,
              {"X", "mc.x", FT_DOUBLE, BASE_DEC, NULL, 0x0, "X Coord", HFILL }
            },
            { &hf_mc_y,
              {"Y", "mc.y", FT_DOUBLE, BASE_DEC, NULL, 0x0, "Y Coord", HFILL }
            },
            { &hf_mc_z,
              {"Z", "mc.z", FT_DOUBLE, BASE_DEC, NULL, 0x0, "Z Coord", HFILL }
            },
            { &hf_mc_stance,
              {"Stance", "mc.stance", FT_DOUBLE, BASE_DEC, NULL, 0x0, "Stance", HFILL }
            },
            { &hf_mc_rotation,
              {"Rotation", "mc.rotation", FT_FLOAT, BASE_DEC, NULL, 0x0, "Rotation", HFILL }
            },
            { &hf_mc_pitch,
              {"Pitch", "mc.pitch", FT_FLOAT, BASE_DEC, NULL, 0x0, "Pitch", HFILL }
            },
            { &hf_mc_status,
              {"Status", "mc.status", FT_INT8, BASE_DEC, NULL, 0x0, "Status", HFILL }
            },
            { &hf_mc_xbyte,
              {"X", "mc.xbyte", FT_INT8, BASE_DEC, NULL, 0x0, "X Offset", HFILL }
            },
            { &hf_mc_ybyte,
              {"Y", "mc.ybyte", FT_INT8, BASE_DEC, NULL, 0x0, "Y Offset", HFILL }
            },
            { &hf_mc_zbyte,
              {"Z", "mc.zbyte", FT_INT8, BASE_DEC, NULL, 0x0, "Z Offset", HFILL }
            },
            { &hf_mc_yshort,
              {"Y", "mc.yshort", FT_INT16, BASE_DEC, NULL, 0x0, "Y Coord", HFILL }
            },
            { &hf_mc_dig,
              {"Dig", "mc.dig", FT_INT8, BASE_DEC, NULL, 0x0, "Digging/Stopped/Broken", HFILL }
            },
            { &hf_mc_block_type,
              {"Block/Item Type", "mc.block_type", FT_INT16, BASE_DEC, NULL, 0x0, "Block/Item Type", HFILL }
            },
            { &hf_mc_direction,
              {"Direction", "mc.direction", FT_INT8, BASE_DEC, VALS(directionnames), 0x0, "Direction", HFILL }
            },
            { &hf_mc_int_coords,
              {"Coordinates", "mc.coords", FT_NONE, BASE_NONE, NULL, 0x0, "Coordinates", HFILL }
            },
            { &hf_mc_xint,
              {"X", "mc.xint", FT_INT32, BASE_DEC, NULL, 0x0, "X Coord", HFILL }
            },
            { &hf_mc_yint,
              {"Y", "mc.yint", FT_INT32, BASE_DEC, NULL, 0x0, "Y Coord", HFILL }
            },
            { &hf_mc_zint,
              {"Z", "mc.zint", FT_INT32, BASE_DEC, NULL, 0x0, "Z Coord", HFILL }
            },
            { &hf_mc_unique_id,
              {"Unique ID", "mc.unique_id", FT_INT32, BASE_DEC, NULL, 0x0, "Unique ID", HFILL }
            },
            { &hf_mc_unknown_byte,
              {"Unknown Byte", "mc.unknown_byte", FT_INT8, BASE_DEC, NULL, 0x0, "Unknown Byte", HFILL }
            },
            { &hf_mc_rotation_byte,
              {"Rotation Byte", "mc.rotation_byte", FT_INT8, BASE_DEC, NULL, 0x0, "Rotation Byte", HFILL }
            },
            { &hf_mc_pitch_byte,
              {"Pitch", "mc.pitch_byte", FT_INT8, BASE_DEC, NULL, 0x0, "Pitch Byte", HFILL }
            },
            { &hf_mc_size_x,
              {"Size X", "mc.size_x", FT_INT8, BASE_DEC, NULL, 0x0, "X Size", HFILL }
            },
            { &hf_mc_size_y,
              {"Size Y", "mc.size_y", FT_INT8, BASE_DEC, NULL, 0x0, "Y Size", HFILL }
            },
            { &hf_mc_size_z,
              {"Size Z", "mc.size_z", FT_INT8, BASE_DEC, NULL, 0x0, "Z Size", HFILL }
            },
            { &hf_mc_block_type_byte,
              {"Block/Item Type", "mc.block_type_byte", FT_INT8, BASE_DEC, NULL, 0x0, "Block/Item Type", HFILL }
            },
            { &hf_mc_block_meta_byte,
              {"Block Metadata", "mc.block_meta_byte", FT_INT8, BASE_DEC, NULL, 0x0, "Block Metadata", HFILL }
            },
            { &hf_mc_item_code,
              {"Item Code", "mc.item_code", FT_INT16, BASE_DEC, NULL, 0x0, "Item Code", HFILL }
            },
            { &hf_mc_amount,
              {"Amount", "mc.amount", FT_INT8, BASE_DEC, NULL, 0x0, "Amount", HFILL }
            },
            { &hf_mc_life,
              {"Life", "mc.life", FT_INT16, BASE_DEC, NULL, 0x0, "Life", HFILL }
            },
            { &hf_mc_login_protocol_version, {"Protocol Version", "mc.protocol", FT_INT32, BASE_DEC, NULL, 0x0, "Protocol Version", HFILL } },
            { &hf_mc_login_entity_id, {"Player entity ID", "mc.playerid", FT_INT32, BASE_DEC, NULL, 0x0, "Player entity ID", HFILL } },
            { &hf_mc_login_username, {"username", "mc.username", FT_STRING, BASE_NONE, NULL, 0x0, "Text", HFILL} },
            { &hf_mc_login_password, {"password", "mc.username", FT_STRING, BASE_NONE, NULL, 0x0, "Text", HFILL} },
            { &hf_mc_login_map_seed, {"Map seed", "mc.mapseed", FT_INT64, BASE_DEC, NULL, 0x0, "Map seed", HFILL } },
            { &hf_mc_login_dimension, {"Dimension", "mc.dimension", FT_INT8, BASE_DEC, NULL, 0x0, "Dimension", HFILL } },
        };
        proto_minecraft = proto_register_protocol (
                              "Minecraft Beta v9 SMP Protocol", /* name */
                              "Minecraft",          /* short name */
                              "mc"	         /* abbrev */
                          );

        module = prefs_register_protocol(proto_minecraft, proto_reg_handoff_minecraft);

        proto_register_field_array(proto_minecraft, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));

    }
}
