/**
 * @name py_67_80__cwe_079
 * @description py_cwe_079
 * @kind problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision medium
 * @id py_1
 * @tags security
 *       
 */
import python


predicate isFixed(Name name_fixed)
{
    // (
    //     // 64
    //     name_fixed.getId()="werkzeug"
    //     and
    //     name_fixed.getParentNode().(Attribute).getAttr()="utils"
    //     and
    //     name_fixed.getParentNode().(Attribute).getParentNode().(Attribute).getAttr()="secure_filename"
    //     and
    //     name_fixed.getParentNode().(Attribute).getParentNode().(Attribute).getParentNode().(Call).getParentNode().(Call).getAChildNode().(Name).getId()="remove"
    //     and
    //     name_fixed.getParentNode().(Attribute).getParentNode().(Attribute).getParentNode().(Call).getArg(0).(Name).getId()="filename"
    // )
    // or
    // (
    //     // 65
    //     name_fixed.getId()="safe_join"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(0).(BinaryExpr).getAChildNode().(Str).getText()="../Songs/"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(0).(BinaryExpr).getAChildNode().(Name).getId()="value"
    //     and
    //     name_fixed.getParentNode().getParentNode().getAChildNode().(Name).getId()="send_file"
    //     )
    // or
    // (

    // )
    // (
    //     // 67
    //     name_fixed.getId()="safe_join"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(0).(Call).getAChildNode().(Name).getId()="str"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(0).(Call).getArg(0).(Attribute).getAttr()="aws_location"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(0).(Call).getArg(0).(Attribute).getAChildNode().(Name).getId()="storage"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(1).(Call).getAChildNode().(Name).getId()="str"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(1).(Call).getArg(0).(Call).getAChildNode().(Name).getId()="getattr"
    // )
    // or
    // (
    //     // 68
    //     name_fixed.getId()="safe_join"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(0).(Attribute).getAChildNode().(Name).getId()="server"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(0).(Attribute).getAttr()="logs_path"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(1).(Name).getId()="path"
    //     and
    //     name_fixed.getParentNode().getParentNode().(AssignStmt).getAChildNode().(Name).getId()="file_path"
    // )
    // or
    // (   
    //     // 69
    //     name_fixed.getId()="safe_join"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(0).(Subscript).getAChildNode().(Name).getId()="CONFIG"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(0).(Subscript).getAChildNode().(Str).getText()="SRV_DIR"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(1).(Name).getId()="req_path"
    //     and
    //     name_fixed.getParentNode().getParentNode().(AssignStmt).getAChildNode().(Name).getId()="abs_path"
    // )
    // or
    // (
    //     // 70_71_72_73_74_75
    //     name_fixed.getId()="safe_join"
    //     and
    //     (
    //         name_fixed.getParentNode().(Call).getArg(0).(Name).getId()="INDEXDIR"
    //         or
    //         name_fixed.getParentNode().(Call).getArg(0).(Name).getId()="DATAROOT"
    //     )
    //     and
    //     (
    //         name_fixed.getParentNode().(Call).getArg(1).(Name).getId()="index"
    //         or
    //         name_fixed.getParentNode().(Call).getArg(1).(Name).getId()="obj_path"
    //     )
    //     and
    //     name_fixed.getParentNode().getParentNode() instanceof Return
    // )
    // or
    // (
    //     // 76
    //     name_fixed.getId()="safe_join"
    //     and
    //     name_fixed.getParentNode().getParentNode() instanceof AssignStmt
    //     and
    //     name_fixed.getParentNode().(Call).getArg(0).(Name).getId()="job_base_dir"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(1).(Name).getId()="path"
    // )
    // or
    // (
    //     // 77
    //     name_fixed.getId()="safe_join"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(1).(Name).getId()="filename"
    //     and
    //     name_fixed.getParentNode().getParentNode() instanceof AssignStmt
    //     and
    //     name_fixed.getParentNode().(Call).getArg(0).(Call).getAChildNode().(Attribute).getAttr()="get"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(0).(Call).getAChildNode().(Attribute).getAChildNode().(Attribute).getAttr()="config"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(0).(Call).getAChildNode().(Attribute).getAChildNode().(Attribute).getAChildNode().(Name).getId()="app"
    //     )
        // or
        // (
        //     // 78
        //     name_fixed.getId()="safe_join"
        //     and
        //     name_fixed.getParentNode().(Call).getArg(0).(Attribute).getAChildNode().(Name).getId()="current_app"
        //     and
        //     name_fixed.getParentNode().(Call).getArg(0).(Attribute).getAttr()="template_folder"
        //     and
        //     name_fixed.getParentNode().(Call).getArg(1).(Name).getId()="path"
        //     and
        //     name_fixed.getParentNode().getParentNode().(AssignStmt).getAChildNode().(Name).getId()="file_path"
        // )
        // or
        // (
        //     // 79
        // name_fixed.getId()="safe_join"
        // and
        // name_fixed.getParentNode().getParentNode() instanceof AssignStmt
        // and
        // name_fixed.getParentNode().(Call).getArg(0).(Name).getId()="script_dir"
        // and
        // name_fixed.getParentNode().(Call).getArg(1).(Name).getId()="rel_path"
        // )
        // or
        // (
        //     // 80
        //     name_fixed.getId()="abspath"
        //     and
        //     name_fixed.getParentNode().getAChildNode().(Call).getAChildNode().(Attribute).getAChildNode().(Attribute).getAChildNode().(Name).getId()="os"
        //     and
        //     name_fixed.getParentNode().getAChildNode().(Call).getAChildNode().(Attribute).getAChildNode().(Attribute).getAttr()="path"
        //     and
        //     name_fixed.getParentNode().getAChildNode().(Call).getAChildNode().(Attribute).getAttr()="realpath"
        //     and
        //     name_fixed.getParentNode().getAChildNode().(Call).getArg(0).(Call).getAChildNode().(Attribute).getAChildNode().(Attribute).getAChildNode().(Name).getId()="os"
        //     and
        //     name_fixed.getParentNode().getAChildNode().(Call).getArg(0).(Call).getAChildNode().(Attribute).getAChildNode().(Attribute).getAttr()="path"
        //     and
        //     name_fixed.getParentNode().getAChildNode().(Call).getArg(0).(Call).getAChildNode().(Attribute).getAttr()="join"
        //     and
        //     name_fixed.getParentNode().getAChildNode().(Call).getArg(0).(Call).getArg(0).(Name).getId()="component_root"
        //     and
        //     name_fixed.getParentNode().getAChildNode().(Call).getArg(0).(Call).getArg(1).(Name).getId()="filename"
        // )
        // or
        // (
        //         // 81 ignore
        // )
        // (
        //     // 82_83
        //     name_fixed.getId()="staticfile" 
        //     and
        //     (
        //         name_fixed.getParentNode().(Call).getArg(0).(Name).getId()="robots_txt"
        //         or
        //         name_fixed.getParentNode().(Call).getArg(0).(Name).getId()="static_dir"
        //     )
        //     and
        //     (
        //         name_fixed.getParentNode().(Call).getParentNode().(AssignStmt).getAChildNode().(Attribute).getAttr()="static"
        //         or
        //         name_fixed.getParentNode().(Call).getParentNode().(AssignStmt).getAChildNode().(Attribute).getAttr()="robots_txt"
        //     )
        //     and
        //     name_fixed.getParentNode().(Call).getParentNode().(AssignStmt).getAChildNode().(Attribute).getAChildNode().(Name).getId()="self"
        // )
        // or
        // (
        //     // 84_85
        //     name_fixed.getId()="staticfile" 
        //     and
        //     name_fixed.getParentNode().(Call).getArg(0).(Attribute).getAChildNode().(Name).getId()="self"
        //     and
        //     (
        //         name_fixed.getParentNode().(Call).getArg(0).(Attribute).getAttr()="_favicon"
        //         or
        //         name_fixed.getParentNode().(Call).getArg(0).(Attribute).getAttr()="_header_logo"
        //     )
        //     and
        //     name_fixed.getParentNode().(Call).getParentNode().(AssignStmt).getAChildNode().(Attribute).getAChildNode().(Attribute).getAChildNode().(Name).getId()="self"
        //     and
        //     name_fixed.getParentNode().(Call).getParentNode().(AssignStmt).getAChildNode().(Attribute).getAChildNode().(Attribute).getAttr()="root"
        //     and
        //     (
        //         name_fixed.getParentNode().(Call).getParentNode().(AssignStmt).getAChildNode().(Attribute).getAttr()="favicon_ico"
        //         or
        //         name_fixed.getParentNode().(Call).getParentNode().(AssignStmt).getAChildNode().(Attribute).getAttr()="header_logo"
        //     )
        // )
        // or
//         (
//             // 86
//             name_fixed.getId()="self"
//             and
//             name_fixed.getParentNode().(Attribute).getAttr()="normpath"
//             and
//             name_fixed.getParentNode().getParentNode().(Call).getArg(0).(Call).getAChildNode().(Attribute).getAttr()="join"
//             and
//             name_fixed.getParentNode().getParentNode().(Call).getArg(0).(Call).getArg(0).(Name).getId()="directory"
//             and
//             name_fixed.getParentNode().getParentNode().(Call).getArg(0).(Call).getArg(1).(Name).getId()="filename"
//             and
//             name_fixed.getParentNode().getParentNode().getParentNode().(AssignStmt).getAChildNode().(Name).getId()="full"
//         )
            // or
            // (
            //     // 87
            // name_fixed.getId()="get_sanitized_output_path"
            // and
            // name_fixed.getParentNode().(Call).getArg(0).(Name).getId()="outname"
            // and
            // name_fixed.getParentNode().(Call).getArg(1).(Name).getId()="path"
            // )
        // or
        // (
        //     // 88
        //     name_fixed.getId()="get_sanitized_output_path"
        //     and
        //     name_fixed.getParentNode().(Call).getArg(0).(Name).getId()="outname"
        //     and
        //     name_fixed.getParentNode().(Call).getArg(1).(Call).getAChildNode().(Attribute).getAChildNode().(Call).getAChildNode().(Attribute).getAChildNode().(Name).getId()="pathlib"
        //     and
        //     name_fixed.getParentNode().(Call).getArg(1).(Call).getAChildNode().(Attribute).getAChildNode().(Call).getAChildNode().(Attribute).getAttr()="Path"
        //     and
        //     name_fixed.getParentNode().(Call).getArg(1).(Call).getAChildNode().(Attribute).getAttr()="joinpath"
        // )
        // or
        // (
        //     // 89
        //     name_fixed.getId()="tarsafe"
        //     and
        //     name_fixed.getParentNode().(Attribute).getAttr()="open"
        //     and
        //     name_fixed.getParentNode().getParentNode().(Call).getArg(0).(Name).getId()="zippath"
        //     and
        //     name_fixed.getParentNode().getParentNode().(Call).getParentNode().(Attribute).getAttr()="extractall"
        //     and
        //     name_fixed.getParentNode().getParentNode().(Call).getParentNode().getParentNode().(Call).getArg(0).(Name).getId()="unzippedpath"
        //     )
        // or
        // (
        //     // 90
        //     name_fixed.getId()="os"
        //     and
        //     name_fixed.getParentNode().(Attribute).getParentNode().(Attribute).getAttr()="realpath"
        //     and
        //     name_fixed.getParentNode().(Attribute).getAttr()="path"
        //     and
        //     name_fixed.getParentNode().getParentNode().getParentNode().(Call).getArg(0).(Call).getAChildNode().(Attribute).getAttr()="join"
        //     and
        //     name_fixed.getParentNode().getParentNode().getParentNode().(Call).getArg(0).(Call).getAChildNode().(Attribute).getAChildNode().(Attribute).getAttr()="path"
        //     and
        //     name_fixed.getParentNode().getParentNode().getParentNode().(Call).getArg(0).(Call).getAChildNode().(Attribute).getAChildNode().(Attribute).getAChildNode().(Name).getId()="os"
        //     and
        //     name_fixed.getParentNode().getParentNode().getParentNode().(Call).getParentNode().(AssignStmt).getAChildNode().(Name).getId()="dent_path"
        //      )
        // or
        // (
        //     // 92
        //     name_fixed.getId()="path"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAChildNode().(Attribute).getAttr()="resolve"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAChildNode().(Attribute).getAChildNode().(BinaryExpr).getAChildNode().(Call).getAChildNode().(Name).getId()="Path"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAChildNode().(Attribute).getAChildNode().(BinaryExpr).getAChildNode().(Call).getAChildNode().(Attribute).getAChildNode().(Name).getId()="path"
        // )
        // or
        // (
        //         // 93
        // )
        // or
        // (
        //     // 94
        //     name_fixed.getId()="safe_extract"
        //     and
        //     name_fixed.getParentNode().(Call).getArg(0).(Name).getId()="f"
        //     and
        //     name_fixed.getParentNode().(Call).getArg(1).(Name).getId()="temp_dir_path"
        // )
        // or
        // (
        //         // 95
        //         name_fixed.getId()="src_uri"
        //         and
        //         name_fixed.getParentNode().getAChildNode().(BinaryExpr).getAChildNode().(Str).getText()="file://"
        //         and
        //         name_fixed.getParentNode().getAChildNode().(BinaryExpr).getAChildNode().(Call).getAChildNode().(Name).getId()="_get_obj_absolute_path"
        //         and
        //         name_fixed.getParentNode().getAChildNode().(BinaryExpr).getAChildNode().(Call).getArg(0).(Name).getId()="dataset"
        //         and
        //         name_fixed.getParentNode().getAChildNode().(BinaryExpr).getAChildNode().(Call).getArg(1).(Name).getId()="rel_path"
        //         )
        // or
        // (
        //     // 96--no ast
        //     name_fixed.getId()="agent_data"
        //     and
        // )
}

from Name name_fixed, Stmt stmt
where 
isFixed(name_fixed)
select name_fixed, name_fixed.getLocation()," The file is correctly fixed"