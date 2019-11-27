#define HAVE_PLUGINS

#include <epan/proto.h>
#include <epan/proto_data.h>
#include <epan/packet.h>
#include <epan/conversation.h>

#include <ws_attributes.h>
#include <ws_symbol_export.h>

WS_DLL_PUBLIC const gchar plugin_version[] = "0.1.0";
WS_DLL_PUBLIC const int plugin_want_major = 3;
WS_DLL_PUBLIC const int plugin_want_minor = 0;

static dissector_handle_t handle_minecraft;

static int proto_minecraft = -1;

static int hf_minecraft_len = -1;
static int hf_minecraft_id = -1;
static int hf_minecraft_data = -1;

static int ett_minecraft = -1;

int get_varint(tvbuff_t* tvb, guint offset, guint64* value)
{
    *value = 0;
    for (int i = 0; i < 5; i++) {
        guint64 byte = tvb_get_guint8(tvb, offset++);
        *value |= (byte & 0x7f) << (7 * i);
        if (byte < 0x80)
            return i + 1;
    }
    return 0;
}

int get_string(tvbuff_t* tvb, guint offset, gchar** str)
{
    guint64 length;
    guint len = get_varint(tvb, offset, &length);
    *str = tvb_get_string_enc(wmem_packet_scope(), tvb, offset += len, length, ENC_UTF_8);
    return len + length;
}

enum minecraft_state {
    MINECRAFT_HANDSHAKE,
    MINECRAFT_STATUS,
    MINECRAFT_LOGIN,
    MINECRAFT_PLAY
};

struct minecraft_conversation {
    enum minecraft_state state;
};

struct minecraft_packet {
    enum minecraft_state state;
};

int dissect_minecraft(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree)
{
    conversation_t* conversation = find_or_create_conversation(pinfo);
    struct minecraft_conversation* conv_data;

    conv_data = (struct minecraft_conversation*)conversation_get_proto_data(conversation, proto_minecraft);
    if (!conv_data) {
        conv_data = wmem_new(wmem_file_scope(), struct minecraft_conversation);
        conv_data->state = MINECRAFT_HANDSHAKE;
        conversation_add_proto_data(conversation, proto_minecraft, conv_data);
    }

    struct minecraft_packet* packet_info = p_get_proto_data(wmem_file_scope(), pinfo, proto_minecraft, 0);

    if (!packet_info) {
        packet_info = wmem_new(wmem_file_scope(), struct minecraft_packet);
        packet_info->state = conv_data->state;
        p_add_proto_data(wmem_file_scope(), pinfo, proto_minecraft, 0, packet_info);
    }

    guint offset = 0;

    while (offset < tvb_reported_length(tvb)) {
        gint remaining = tvb_reported_length_remaining(tvb, offset);
        guint start = offset;

        guint64 length;
        offset += get_varint(tvb, offset, &length);

        if (offset == start || length > remaining) {
            pinfo->desegment_offset = start;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            return -1;
        }

        guint end = offset + length;

        proto_item* item = proto_tree_add_item(tree, proto_minecraft, tvb, start, end - start, ENC_NA);
        proto_tree* subtree = proto_item_add_subtree(item, ett_minecraft);

        guint64 id;
        guint len = get_varint(tvb, offset, &id);

        proto_tree_add_uint(subtree, hf_minecraft_len, tvb, start, offset - start, length);
        proto_tree_add_uint(subtree, hf_minecraft_id, tvb, offset, len, id);
        offset += len;
        proto_tree_add_item(subtree, hf_minecraft_data, tvb, offset, end - offset, 0);

        gint serverbound = pinfo->match_uint == pinfo->destport;

        if (serverbound && packet_info->state == MINECRAFT_HANDSHAKE && id == 0) {
            guint64 protocol;
            offset += get_varint(tvb, offset, &protocol);
            gchar* host;
            offset += get_string(tvb, offset, &host);
            guint16 port = tvb_get_guint16(tvb, offset, 0);
            offset += 2;
            guint64 state;
            offset += get_varint(tvb, offset, &state);
            conv_data->state = state;
        } else if (!serverbound && packet_info->state == MINECRAFT_LOGIN && id == 2) {
            conv_data->state = MINECRAFT_PLAY;
        }

        col_set_str(pinfo->cinfo, COL_PROTOCOL, "MC");
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s 0x%02x", serverbound ? "C->S" : "S->C", id);

        offset += end;
    }

    return offset;
}

void proto_register_minecraft()
{
    static hf_register_info hf[] = {
        { &hf_minecraft_len,
            { "Packet Length", "mc.len", FT_UINT32, BASE_DEC, NULL, 0x0, NULL,
                HFILL } },
        { &hf_minecraft_id,
            { "Packet Type", "mc.id", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_minecraft_data,
            { "Packet Data", "mc.data", FT_BYTES, 0, NULL, 0x0, NULL, HFILL } }
    };

    static gint* ett[] = { &ett_minecraft };

    proto_minecraft = proto_register_protocol("Minecraft Java Protocol", "Minecraft", "mc");

    proto_register_field_array(proto_minecraft, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

static void proto_reg_handoff_minecraft()
{
    handle_minecraft = create_dissector_handle(dissect_minecraft, proto_minecraft);
    dissector_add_uint_with_preference("tcp.port", 25565, handle_minecraft);
}

WS_DLL_PUBLIC void plugin_register(void)
{
    static proto_plugin plug;

    plug.register_protoinfo = proto_register_minecraft;
    plug.register_handoff = proto_reg_handoff_minecraft;
    proto_register_plugin(&plug);
}
