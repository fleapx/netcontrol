#ifndef TAURUS_CJSON_GLUE_H
#define TAURUS_CJSON_GLUE_H

#include <string>
#include <vector>
#include "jansson.h"

// 这里将实现与定义混写避免某些情况编译失败
class CJsonWrapper{
public:
    typedef json_t* NodeType;
    typedef const json_t* CNodeType; 
    
    static NodeType parse_text(
        const std::string& src          // 待解析json串
    ) { // need release
        return json_loads(src.c_str(), 0, 0); // ref+1
    }
    
    static bool contain_item(
        NodeType node,                  // 目标object节点
        const std::string& tag          // 目标key
    ) {
        return json_object_get(node, tag.c_str()) != 0;
    }
    
    static bool get_object_string_node(
        NodeType node,                  // 目标节点
        const std::string& tag,         // 目标key
        std::string& out                // 输出val
    ) {
        bool result = false;
        if (node != 0) {
            NodeType subnode = json_object_get(node, tag.c_str());
            if (subnode != 0) { 
                if (json_is_string(subnode)) {
                    out = json_string_value(subnode);
                    result = true;
                }
            }
        }
        return result;
    }
    
    template <typename T>
    static bool get_object_int_node(
        NodeType node,                  // 目标节点
        const std::string& tag,         // 目标key
        T& out                          // 输出val
    ) {
        bool result = false;
        if (node != 0) {
            NodeType subnode = json_object_get(node, tag.c_str());
            if (subnode != 0) {
                if (json_is_integer(subnode)) {
                    out = json_integer_value(subnode);
                    result = true;
                }
            }
        }
        return result;
    }
    
    static bool get_object_object_node(
        NodeType node,                  // 目标节点
        const std::string& tag,         // 目标key
        NodeType& out                   // 输出val
    ) {
        if (node != 0) {
            NodeType subnode = json_object_get(node, tag.c_str());
            if (subnode != 0) {
                out = subnode;
                return true;
            }
        }
        return false;
    }
    
    static bool set_object_string_node(
        NodeType node,                  // 目标节点
        const std::string& tag,         // 目标key
        const std::string& in           // 输入val
    ) {
        if (node != 0) {
            return 0 == json_object_set_new(node, tag.c_str(), json_string(in.c_str())); 
            // 0 if success
        }
        return false;
    }
    
    static bool set_object_int_node(
        NodeType node,                  // 目标节点
        const std::string& tag,         // 目标key
        const int in                    // 输入val
    ) {
        if (node != 0) {
            return 0 == json_object_set_new(node, tag.c_str(), json_integer(in)); 
            // 0 if success
        }
        return false;
    }
    
    static bool set_object_object_node(
        NodeType node,                  // 目标节点
        const std::string& tag,         // 目标key
        const NodeType in               // 输入val
    ) {
        if (node != 0) {
            return 0 == json_object_set_new(node, tag.c_str(), in); // 0 if success
        }
        return false;
    }
    
    static std::vector<std::string> get_object_keys(NodeType node) { 
        std::vector<std::string> keys;
        void* iter = json_object_iter(node);
        char* key = 0;
        while (iter != 0) {
            key = (char*)json_object_iter_key(iter);
            if (key != 0) {
                keys.push_back(key);
            }
            iter = json_object_iter_next(node, iter);
        }
        return keys;
    }
    
    static bool is_object(NodeType node) {
        return json_is_object(node);
    }
    
    static bool is_array(NodeType node) {
        return json_is_array(node);
    }
    
    static bool is_true(NodeType node) {
        return json_is_true(node);
    }
    
    static bool is_false(NodeType node) {
        return json_is_false(node);
    }
    
    static int get_array_size(NodeType node) {
        if (node != 0) {
            return json_array_size(node);
        }
        return 0;
    }
    
    static bool get_array_string_node(
        NodeType node,              // 目标节点
        int index,                  // 目标key
        std::string& out            // 输出val
    ) {
        if (node != 0) {
            NodeType subnode = json_array_get(node, index);
            if (subnode != 0 && json_is_string(subnode)) {
                out = (char*)json_string_value(subnode);
                return true;
            }
        }
        return false;
    }
    
    static bool get_array_int_node(
        NodeType node,              // 目标节点
        int index,                  // 目标key
        int& out                    // 输出val
    ) {
        if (node != 0) {
            NodeType subnode = json_array_get(node, index);
            if (subnode != 0 && json_is_integer(subnode)) {
                out = json_integer_value(subnode);
                return true;
            }
        }
        return false;
    }
    
    static bool get_array_object_node(
        NodeType node,              // 目标节点
        int index,                  // 目标key
        NodeType& out               // 输出val
    ) {
        if (node != 0) {
            NodeType subnode = json_array_get(node, index);
            if (subnode != 0) {
                out = subnode;
                return true;
            }
        }
        return false;
    }
    
    static NodeType create_object_node() {
        return json_object();
    }
    
    static NodeType create_array_node() {
        return json_array();
    }
    
    static NodeType duplicate_node(NodeType node) { // need release
        return json_copy(node); // ref+1
    }
    
    static bool add_object_string_node(
        NodeType node,                  // 目标节点
        const std::string& tag,         // 目标key
        const std::string& in           // 输入val
    ) {
        if (node != 0) {
            return 0 == json_object_set_new_nocheck(node, tag.c_str(), json_string(in.c_str()));
        }
        return false;
    }
    static bool add_object_int_node(
        NodeType node,                  // 目标节点
        const std::string& tag,         // 目标key
        const int in                    // 输入val
    ) {
        if (node != 0) {
            return 0 == json_object_set_new_nocheck(node, tag.c_str(), json_integer(in));
        }
        return false;
    }
    
    static bool add_object_object_node(
        NodeType node,                  // 目标节点
        const std::string& tag,         // 目标key
        const NodeType in               // 输入val
    ) {
        if (node != 0) {
            return 0 == json_object_set_new_nocheck(node, tag.c_str(), in);
        }
        return false;
    }
    
    static bool add_array_string_node(
        NodeType node,                  // 目标节点
        const std::string& in           // 输入val
    ) {
        if (node != 0) {
            return 0 == json_array_append_new(node, json_string(in.c_str()));
        }
        return false;
    }
    
    static bool add_array_int_node(
        NodeType node,                  // 目标节点
        const int in                    // 输入val
    ) {
        if (node != 0) {
            return 0 == json_array_append_new(node, json_integer(in));
        }
        return false;
    }
    
    static bool add_array_object_node(
        NodeType node,                  // 目标节点
        const NodeType in               // 输入val
    ) {
        if (node != 0) {
            return 0 == json_array_append_new(node, in);
        }
        return false;
    }
    
    static bool get_json_string(
        NodeType node,                  // 目标节点
        std::string& output             // 输出文本
    ) {
        char* s = json_dumps(node, JSON_INDENT(0));
        if (s != 0) {
            output = s;
            free(s);
        } else {
            return false;
        }
        return true;
    }
    
    static void release_root_node(NodeType node) {
        json_decref(node);
    }
};

#endif //TAURUS_CJSON_GLUE_H
