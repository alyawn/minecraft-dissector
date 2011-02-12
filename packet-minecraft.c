#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gmodule.h>
#include <epan/prefs.h>
#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>


/* forward reference */
void proto_register_minecraft();
void proto_reg_handoff_minecraft();
void dissect_minecraft(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Define version if we are not building Wireshark statically */
#ifndef ENABLE_STATIC
G_MODULE_EXPORT const gchar version[] = "0.0";
#endif

#define PROTO_TAG_MC "MC"

static int proto_minecraft = -1;
static dissector_handle_t minecraft_handle;

proto_item *mc_item = NULL;
proto_item *mc_sub_item = NULL;
proto_tree *mc_tree = NULL;
proto_tree *mc_header_tree = NULL;

#include "packet-minecraft-names.h"

static const value_string directionnames[] = {
    {0, "-Y"},
    {1, "+Y"},
    {2, "-Z"},
    {3, "+Z"},
    {4, "-X"},
    {5, "+X"},
    {0, NULL}
};

#ifndef ENABLE_STATIC
G_MODULE_EXPORT void plugin_register(void)
{
    /* register the new protocol, protocol fields, and subtrees */
    if (proto_minecraft == -1) { /* execute protocol initialization only once */
        proto_register_minecraft();
    }
}

G_MODULE_EXPORT void plugin_reg_handoff(void) {
    proto_reg_handoff_minecraft();
}
#endif

static gint ett_mc = -1;
static gint ett_mc_double_coords = -1;
static gint ett_mc_int_coords = -1;

/* Setup protocol subtree array */
static gint *ett[] = {
    &ett_mc,
    &ett_mc_double_coords,
    &ett_mc_int_coords
};

#include "packet-minecraft-hfint.h"

#include "packet-minecraft-register.h"

void proto_reg_handoff_minecraft(void)
{
    static int Initialized=FALSE;

    /* register with wireshark to dissect udp packets on port 25565 */
    if (!Initialized) {
        minecraft_handle = create_dissector_handle(dissect_minecraft, proto_minecraft);
        dissector_add("tcp.port", 25565, minecraft_handle);
    }
}

static guint metadata_len(tvbuff_t * tvb, guint offset, guint available)
{
    guint len;
    len = 0;
    while(1) {
        guint8 x;
        if( (offset+len+1) > available ) { return -1; }
        len += 1;
        x = tvb_get_guint8(tvb, offset + len - 1);
        if(x == 127) { return len; }
        switch(x >> 5) {
            case 0:  len += 1; break; /* int8 */
            case 1:  len += 2; break; /* int16 */
            case 2:  len += 4; break; /* int32 */
            case 3:  len += 4; break; /* float32 */
            case 4:                   /* string */
                if( (offset+len+2) > available ) { return -1; }
                len += 2 + tvb_get_ntohs(tvb, offset+len);
                break;
            case 5:  len += 5; break; /* int16, int8, int16 */
            default: len += 4; break; /* TODO: Eeeee! */
        }
    }
    DISSECTOR_ASSERT(0); /* Loop should never exit */ 
}

static gint32 tvb_get_ntohint(tvbuff_t * tvb, guint offset, guint size)
{
    switch(size) {
        case 1: return (gint32)tvb_get_guint8(tvb, offset); 
        case 2: return (gint32)tvb_get_ntohs(tvb, offset); 
        case 3: return (gint32)tvb_get_ntoh24(tvb, offset); 
        case 4: return (gint32)tvb_get_ntohl(tvb, offset); 
        /*case 5: return (gint32)tvb_get_ntoh40(tvb, offset); */
        /*case 6: return (gint32)tvb_get_ntoh48(tvb, offset); */
        /*case 7: return (gint32)tvb_get_ntoh56(tvb, offset); */
        case 8: return (gint32)tvb_get_ntoh64(tvb, offset); 
        default: break;
    }
    DISSECTOR_ASSERT(FALSE);
    return 0;
}

static void proto_tree_add_item_varint(proto_tree *tree, gint hf_id_byte, gint hf_id_quad, tvbuff_t * tvb, guint32 offset, guint32 size)
{
    if(size == 1) {
        proto_tree_add_item(tree, hf_id_byte, tvb, offset, 1, FALSE);
    } else {
        proto_tree_add_item(tree, hf_id_quad, tvb, offset, 4, FALSE);
    }
}

static void add_int_coordinates( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset, guint32 xoffset, guint x_size, guint32 yoffset, guint y_size, guint32 zoffset, guint z_size)
{
    proto_item *ti;
    proto_tree * coord_tree;
    gint32 x,y,z;

    x = tvb_get_ntohint(tvb, offset+xoffset, x_size);
    y = tvb_get_ntohint(tvb, offset+yoffset, y_size);
    z = tvb_get_ntohint(tvb, offset+zoffset, z_size);

    ti = proto_tree_add_none_format(tree, hf_mc_int_coords, tvb, offset, -1, "Coordinates: %d, %d, %d", (gint32)tvb_get_ntohl(tvb, offset+xoffset), y, (gint32)tvb_get_ntohl(tvb, offset+zoffset));
    coord_tree = proto_item_add_subtree(ti, ett_mc_int_coords);

    proto_tree_add_item_varint(coord_tree, hf_mc_xbyte, hf_mc_xint, tvb, offset+xoffset, 4);
    proto_tree_add_item_varint(coord_tree, hf_mc_ybyte, hf_mc_yint, tvb, offset+yoffset, 4);
    proto_tree_add_item_varint(coord_tree, hf_mc_zbyte, hf_mc_zint, tvb, offset+zoffset, 4);
}

static void add_double_coordinates( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset, guint32 xoffset, guint32 yoffset, guint32 zoffset)
{
    proto_item *ti;
    proto_tree * coord_tree;
    ti = proto_tree_add_none_format(tree, hf_mc_double_coords, tvb, offset, -1, "Coordinates: %f, %f, %f", tvb_get_ntohieee_double(tvb, offset+xoffset), tvb_get_ntohieee_double(tvb, offset+yoffset), tvb_get_ntohieee_double(tvb, offset+zoffset));
    coord_tree = proto_item_add_subtree(ti, ett_mc_double_coords);
    proto_tree_add_item(coord_tree, hf_mc_x, tvb, offset + xoffset, 8, FALSE);
    proto_tree_add_item(coord_tree, hf_mc_y, tvb, offset + yoffset, 8, FALSE);
    proto_tree_add_item(coord_tree, hf_mc_z, tvb, offset + zoffset, 8, FALSE);
}


static void add_login_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset, gboolean c2s)
{
    guint16 strlen1, strlen2;

    offset += 1;

    proto_tree_add_item(tree, c2s?hf_mc_login_protocol_version:hf_mc_login_entity_id, tvb, offset, 4, FALSE);
    offset += 4;

    strlen1 = tvb_get_ntohs( tvb, offset );
    offset += 2;
    proto_tree_add_item(tree, c2s?hf_mc_login_username:hf_mc_server_name, tvb, offset, strlen1, FALSE);
    offset += strlen1;

    strlen2 = tvb_get_ntohs( tvb, offset );
    offset += 2;
    proto_tree_add_item(tree, c2s?hf_mc_login_password:hf_mc_motd, tvb, offset, strlen2, FALSE);
    offset += strlen2;

    proto_tree_add_item(tree, hf_mc_login_map_seed, tvb, offset, 8, FALSE);
    offset += 8;
    proto_tree_add_item(tree, hf_mc_login_dimension, tvb, offset, 1, FALSE);
}

static void add_handshake_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset, gboolean c2s)
{
    guint16 strlen1;
    gint hf = c2s ? hf_mc_username : hf_mc_serverid;

    strlen1 = tvb_get_ntohs( tvb, offset + 1 );
    proto_tree_add_item(tree, hf, tvb, offset + 3, strlen1, FALSE);
}

static void add_chat_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    guint16 strlen1;

    strlen1 = tvb_get_ntohs( tvb, offset + 1 );
    proto_tree_add_item(tree, hf_mc_chat, tvb, offset + 3, strlen1, FALSE);
}
static void add_time_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    guint64 time;

    time = tvb_get_ntoh64(tvb, offset + 1 );
    proto_tree_add_item(tree, hf_mc_time, tvb, offset + 1, 8, FALSE);
}
static void add_loaded_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_loaded, tvb, offset + 1, 1, FALSE);
}
static void add_player_position_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    add_double_coordinates(tree, tvb, pinfo, offset, 1, 9, 25);
    proto_tree_add_item(tree, hf_mc_stance, tvb, offset + 17, 8, FALSE);

}
static void add_player_look_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{

    proto_tree_add_item(tree, hf_mc_rotation, tvb, offset + 1, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_pitch, tvb, offset + 5, 4, FALSE);

}
static void add_player_move_look_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    add_double_coordinates(tree, tvb, pinfo, offset, 1, 9, 25);
    proto_tree_add_item(tree, hf_mc_stance, tvb, offset + 17, 8, FALSE);

    proto_tree_add_item(tree, hf_mc_rotation, tvb, offset + 33, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_pitch, tvb, offset + 37, 4, FALSE);

}
static void add_block_dig_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_status, tvb, offset + 1, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_xint, tvb, offset + 2, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_ybyte, tvb, offset + 6, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_zint, tvb, offset + 7, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_direction, tvb, offset + 11, 1, FALSE);

}
static void add_place_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_block_type, tvb, offset + 1, 2, FALSE);
    proto_tree_add_item(tree, hf_mc_xint, tvb, offset + 3, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_ybyte, tvb, offset + 7, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_zint, tvb, offset + 8, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_direction, tvb, offset + 12, 1, FALSE);

}
/* TODO DEAD?
static void add_block_item_switch_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_unique_id, tvb, offset + 1, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_item_code, tvb, offset + 5, 2, FALSE);
}
*/

static void add_change_slot_selection( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset, gboolean c2s)
{
    proto_tree_add_item(tree, hf_mc_inventory_slot, tvb, offset + 1, 2, FALSE);
}

static void add_add_to_inventory_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_block_type, tvb, offset + 1, 2, FALSE);
    proto_tree_add_item(tree, hf_mc_amount, tvb, offset + 3, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_life, tvb, offset + 4, 2, FALSE);
}
static void add_arm_animation_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_unique_id, tvb, offset + 1, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_unknown_byte, tvb, offset + 5, 1, FALSE);
}
static void add_named_entity_spawn_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    int name_len, o2;
    proto_tree_add_item(tree, hf_mc_unique_id, tvb, offset + 1, 4, FALSE);
    name_len = tvb_get_ntohs(tvb, offset + 5);
    proto_tree_add_item(tree, hf_mc_username, tvb, offset + 7, name_len, FALSE);

    o2 = offset + 7 + name_len;
    proto_tree_add_item(tree, hf_mc_xint, tvb, o2, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_yint, tvb, o2 + 4, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_zint, tvb, o2 + 8, 4, FALSE);

    proto_tree_add_item(tree, hf_mc_rotation_byte, tvb, o2 + 12, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_pitch_byte, tvb, o2 + 13, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_item_code, tvb, o2 + 14, 2, FALSE);


}

static void add_pickup_spawn_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{

    proto_tree_add_item(tree, hf_mc_unique_id, tvb, offset + 1, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_block_type, tvb, offset + 5, 2, FALSE);
    proto_tree_add_item(tree, hf_mc_count, tvb, offset + 7, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_damage, tvb, offset + 8, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_xint, tvb, offset + 10, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_yint, tvb, offset + 14, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_zint, tvb, offset + 18, 4, FALSE);

    proto_tree_add_item(tree, hf_mc_rotation_byte, tvb, offset + 22, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_pitch_byte, tvb, offset + 23, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_roll_byte, tvb, offset + 24, 1, FALSE);
}

static void add_pre_chunk_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_xint, tvb, offset + 1, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_zint, tvb, offset + 5, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_ybyte, tvb, offset + 9, 1, FALSE);
}
static void add_map_chunk_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_xint, tvb, offset + 1, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_yshort, tvb, offset + 5, 2, FALSE);
    proto_tree_add_item(tree, hf_mc_zint, tvb, offset + 7, 4, FALSE);

    proto_tree_add_item(tree, hf_mc_size_x, tvb, offset + 11, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_size_y, tvb, offset + 12, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_size_z, tvb, offset + 13, 1, FALSE);

}
static void add_block_change_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_xint, tvb, offset + 1, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_ybyte, tvb, offset + 5, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_zint, tvb, offset + 6, 4, FALSE);

    proto_tree_add_item(tree, hf_mc_block_type_byte, tvb, offset + 10, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_block_meta_byte, tvb, offset + 11, 1, FALSE);

}
static void add_spawn_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    add_int_coordinates(tree, tvb, pinfo, offset, 1, 4, 5, 4, 9, 4);
}

static void add_complex_entity_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_xint, tvb, offset + 1, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_yshort, tvb, offset + 5, 2, FALSE);
    proto_tree_add_item(tree, hf_mc_zint, tvb, offset + 7, 4, FALSE);

}
static void add_collect_item_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_unique_id, tvb, offset + 1, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_xbyte, tvb, offset + 5, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_ybyte, tvb, offset + 6, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_zbyte, tvb, offset + 7, 1, FALSE);
}
static void add_object_vehicle_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_unique_id, tvb, offset + 1, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_type, tvb, offset + 5, 1, FALSE);

    proto_tree_add_item(tree, hf_mc_xint, tvb, offset + 6, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_yint, tvb, offset + 10, 4, FALSE);
    proto_tree_add_item(tree, hf_mc_zint, tvb, offset + 14, 4, FALSE);
}
static void add_destroy_entity_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_unique_id, tvb, offset + 1, 4, FALSE);
}
static void add_relative_entity_move_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_unique_id, tvb, offset + 1, 4, FALSE);

    proto_tree_add_item(tree, hf_mc_xbyte, tvb, offset + 5, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_ybyte, tvb, offset + 6, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_zbyte, tvb, offset + 7, 1, FALSE);

}
static void add_entity_look_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_unique_id, tvb, offset + 1, 4, FALSE);

    proto_tree_add_item(tree, hf_mc_rotation_byte, tvb, offset + 5, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_pitch_byte, tvb, offset + 6, 1, FALSE);

}
static void add_relative_entity_move_look_details( proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 offset)
{
    proto_tree_add_item(tree, hf_mc_unique_id, tvb, offset + 1, 4, FALSE);

    proto_tree_add_item(tree, hf_mc_xbyte, tvb, offset + 5, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_ybyte, tvb, offset + 6, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_zbyte, tvb, offset + 7, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_rotation_byte, tvb, offset + 8, 1, FALSE);
    proto_tree_add_item(tree, hf_mc_pitch_byte, tvb, offset + 9, 1, FALSE);

}

static void dissect_minecraft_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 type,  guint32 offset, guint32 length)
{
    gboolean c2s;
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_MC);
    /* Clear out stuff in the info column */
//    if(check_col(pinfo->cinfo,COL_INFO)){
//        col_clear(pinfo->cinfo,COL_INFO);
//    }
    c2s = pinfo->match_port == pinfo->destport;

    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_add_fstr(pinfo->cinfo, COL_INFO, c2s ? "C->S" : "S->C" ": %d > %d Info Type:[%s]",
                     pinfo->srcport, pinfo->destport,
                     val_to_str(type, packettypenames, "Unknown Type:0x%02x"));
    }
    if ( tree ) {
        mc_item = proto_tree_add_item(tree, proto_minecraft, tvb, offset, length, FALSE);
        mc_tree = proto_item_add_subtree(mc_item, ett_mc);

        proto_tree_add_item(mc_tree, hf_mc_type, tvb, offset, 1, FALSE);
        proto_tree_add_item(mc_tree, hf_mc_data, tvb, offset, length, FALSE);
        switch (type) {
        case 0x01:
            add_login_details(mc_tree, tvb, pinfo, offset, c2s);
            break;
        case 0x02:
            add_handshake_details(mc_tree, tvb, pinfo, offset, c2s);
            break;
        case 0x03:
            add_chat_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x04:
            add_time_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x06:
            add_spawn_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x0A:
            add_loaded_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x0B:
            add_player_position_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x0C:
            add_player_look_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x0D:
            add_player_move_look_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x0E:
            add_block_dig_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x0F:
            add_place_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x10:
            add_change_slot_selection(mc_tree, tvb, pinfo, offset, c2s);
            break;
        case 0x11:
            add_add_to_inventory_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x12:
            add_arm_animation_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x14:
            add_named_entity_spawn_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x15:
            add_pickup_spawn_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x16:
            add_collect_item_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x17:
            add_object_vehicle_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x1D:
            add_destroy_entity_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x1F:
            add_relative_entity_move_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x20:
            add_entity_look_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x21:
            add_relative_entity_move_look_details(mc_tree, tvb, pinfo, offset);
            break;
            /* ... */
        case 0x32:
            add_pre_chunk_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x33:
            add_map_chunk_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x35:
            add_block_change_details(mc_tree, tvb, pinfo, offset);
            break;
        case 0x3b:
            add_complex_entity_details(mc_tree, tvb, pinfo, offset);
            break;
        }
    }
}

guint get_minecraft_message_len(guint8 type,guint offset, guint available, tvbuff_t *tvb) {
    guint len=-1;
    switch (type) {
    case 0x00: return 1;
    case 0x01:
    {
        int len_strA, len_strB;
        if ( available >= 7 ) {
            len_strA = tvb_get_ntohs(tvb, offset + 5);
            if ( available >= 9 + len_strA ) {
                len_strB = tvb_get_ntohs(tvb, offset + 7 + len_strA);
                len = 5 + (2 + len_strA) + (2 + len_strB) + 9;
            }
        }
    }
    break;
    case 0x02:
        if ( available >= 3 ) {
            len = 3 + tvb_get_ntohs(tvb, offset + 1);
        }
        break;
    case 0x03:
        if ( available >= 3 ) {
            len = 3 + tvb_get_ntohs(tvb, offset + 1);
        }
        break;
    case 0x04: return 9;
    case 0x05:
    {
        if ( available >= 7 ) {
            int num_inv, o, size, count;
            gint16 val;
            num_inv = tvb_get_ntohs(tvb, offset + 5);
            o = offset + 7;
            size = 0;
            count = 0;
            while ( o-offset < available && available -(o-offset) >= 2 && count != num_inv ) {
                count++;

                val = tvb_get_ntohs(tvb, o);
                if ( val == -1 ) {
                    size += 2;
                    o += 2;
                } else {
                    size += 5;
                    o += 5;
                }
            }
            if ( count == num_inv ) {
                len = 7 + size;
            }
        }
    }
    break;
    case 0x06: return 13;
    case 0x0A: return 2;
    case 0x0B: return 34;
    case 0x07: return 9;
    case 0x08: return 3;
    case 0x0C: return 10;
    case 0x0D: return 42;
    case 0x0E: return 12;
    case 0x0F: return 13;
    case 0x10: return 3;
    case 0x11: return 6;
    case 0x12: return 6;
    case 0x15: return 25;
    case 0x16: return 9;
    case 0x17: return 18;
    case 0x18:
        if(available < 21) { return -1; }
        /* Find termination byte 0x7f */
        for(len = 21;
            (len <= available) && (tvb_get_guint8(tvb, offset+len-1) != 0x7f);
            len++) { }
        if(len > available){
            /* TODO OPTIMIZATION: Cache len so we can start where we left off, 
               instead of starting from scratch each time */
            return -1;
        }
        return len;
    case 0x19: 
        if(available < 23) { return -1; }
        return 23 + tvb_get_ntohs(tvb, offset+5);
        break;
    case 0x1C: return 11;
    case 0x1D: return 5;
    case 0x1E: return 5;
    case 0x1F: return 8;
    case 0x20: return 7;
    case 0x21: return 10;
    case 0x22: return 19;
    case 0x27: return 9;
    case 0x28: return 5 + metadata_len(tvb, offset + 5, available);
    case 0x32: return 10;
    case 0x33:
        if ( available >= 18 ) {
            len = 18 + tvb_get_ntohl(tvb, offset + 14);
        }
        break;
    case 0x34:
        if ( available >= 11 ) {
            // the size we get here is number of elements in the arrays
            // and there are 3 arrays, a short, and two bytes, so multiply by 4
            len = 11 + (4 * tvb_get_ntohs(tvb, offset + 9));
        }
        break;
    case 0x35: return 12;
    case 0x36: return 13;
    case 0x3b:
        if ( available >= 13 ) {
            len = 13 + tvb_get_ntohs(tvb, offset + 11);
        }
        break;
    case 0x3c:
        if(available < 33) { return -1; }
        return 33 + (3 * tvb_get_ntohl(tvb, offset + 33));
    case 0x64:
        if(available < 5) { return -1; }
        return 6 + tvb_get_ntohs(tvb, offset + 3);
    case 0x65: return 2;
    case 0x67:
        len = 6;
        if(available < 6) { return -1; }
        if( ((gint16)tvb_get_ntohs(tvb, offset + 4)) != -1) { len += 3; }
        break;
    case 0x68:
    {
        gint n;
        gint num_items;
        gint16 item_id;
        len = 4;
        if(available < len) { return -1; }
        num_items = tvb_get_ntohs(tvb, offset + 2);

        for(n = 0; n < num_items; n++) {
            if((len+2) > available) { return -1; }
            item_id = tvb_get_ntohs(tvb, offset + len);
            len += 2;
            if(item_id != -1) {
                len += 3;
            }
        }
        break;
    }
    case 0x69: return 6;
    case 0x6A: return 5;
    case 0xff:
        if ( available >= 3 ) {
            len = 3 + tvb_get_ntohs(tvb, offset + 1);
        }
        break;
    default:
        printf("Unknown packet: 0x%x\n", type);
        len = 1; /* Not much we can do here */
    }
    return len;

}

#define FRAME_HEADER_LEN 17
void dissect_minecraft(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8 packet;
    guint offset=0;

    while (offset < tvb_reported_length(tvb)) {
        packet = tvb_get_guint8(tvb, offset);
        gint available = tvb_reported_length_remaining(tvb, offset);
        gint len = get_minecraft_message_len(packet, offset, available, tvb);
        if (len == -1 || len > available) {
            pinfo->desegment_offset = offset;
            if ( len == -1 ) {
                pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            } else {
                pinfo->desegment_len = len - available;
            }
            return;
        }
        dissect_minecraft_message(tvb, pinfo, tree, packet, offset, len);
        offset += len;
    }
}

