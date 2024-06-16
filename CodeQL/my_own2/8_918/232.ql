
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
    //     // 233
    //     name_fixed.getId()="context_path"
    //     and
    //     name_fixed.getParentNode().getAChildNode().(Call).getAChildNode().(Attribute).getAChildNode().(Name).getId()="self"
    //     and
    //     name_fixed.getParentNode().getAChildNode().(Call).getAChildNode().(Attribute).getAttr()="_get_context_path"
    //     and
    //     name_fixed.getParentNode().getAChildNode().(Call).getAnArg().(Name).getId()="host"
    //     and
    //     name_fixed.getParentNode().getAChildNode().(Call).getAnArg().(Name).getId()="port"
    // )
    // or
    // (
    //     // 234
    //     name_fixed.getId()="client_path"
    //     and
    //     name_fixed.getParentNode().(Attribute).getAttr()="startswith"
    //     and
    //     name_fixed.getParentNode().getParentNode().(Call).getAnArg().(Str).getText()="/"
    //     and
    //     name_fixed.getParentNode().getParentNode().getParentNode() instanceof UnaryExpr
    //     and
    //     name_fixed.getParentNode().getParentNode().getParentNode().getParentNode() instanceof If
    // )
    // or
    // (
    //     // 235
    //     name_fixed.getId()="url_path_join"
    //     and
    //     name_fixed.getParentNode().(Call).getAnArg().(Subscript).getAChildNode().(Attribute).getAChildNode().(Name).getId()="web_app"
    //     and
    //     name_fixed.getParentNode().(Call).getAnArg().(Subscript).getAChildNode().(Attribute).getAttr()="settings"
    //     and
    //     name_fixed.getParentNode().(Call).getAnArg().(Subscript).getAChildNode().(Str).getText()="base_url"
    //     and
    //     name_fixed.getParentNode().(Call).getAnArg().(Str).getText()="/proxy/([^/:@]+):(\\d+)(/.*|)"
    // )
    // or
    //     (
    //     // 236
    //     name_fixed.getId()="url_path_join"
    //     and
    //     name_fixed.getParentNode().(Call).getAnArg().(Subscript).getAChildNode().(Attribute).getAChildNode().(Name).getId()="web_app"
    //     and
    //     name_fixed.getParentNode().(Call).getAnArg().(Subscript).getAChildNode().(Attribute).getAttr()="settings"
    //     and
    //     name_fixed.getParentNode().(Call).getAnArg().(Subscript).getAChildNode().(Str).getText()="base_url"
    //     and
    //     name_fixed.getParentNode().(Call).getAnArg().(Str).getText()="/proxy/absolute/([^/:@]+):(\\d+)(/.*|)"
    // )
    // or
    // (
    //     // 237
    //     name_fixed.getId()="url_path_join"
    //     and
    //     name_fixed.getParentNode().(Call).getAnArg().(Subscript).getAChildNode().(Attribute).getAChildNode().(Name).getId()="web_app"
    //     and
    //     name_fixed.getParentNode().(Call).getAnArg().(Subscript).getAChildNode().(Attribute).getAttr()="settings"
    //     and
    //     name_fixed.getParentNode().(Call).getAnArg().(Subscript).getAChildNode().(Str).getText()="base_url"
    //     and
    //     name_fixed.getParentNode().(Call).getAnArg().(Str).getText()="/proxy/(\\d+)(/.*|)"
    // )
    // or
    // (
    //     // 238
    //     name_fixed.getId()="url_path_join"
    //     and
    //     name_fixed.getParentNode().(Call).getAnArg().(Subscript).getAChildNode().(Attribute).getAChildNode().(Name).getId()="web_app"
    //     and
    //     name_fixed.getParentNode().(Call).getAnArg().(Subscript).getAChildNode().(Attribute).getAttr()="settings"
    //     and
    //     name_fixed.getParentNode().(Call).getAnArg().(Subscript).getAChildNode().(Str).getText()="base_url"
    //     and
    //     name_fixed.getParentNode().(Call).getAnArg().(Str).getText()="/proxy/absolute/(\\d+)(/.*|)"
    // )
    // or
    // (
    //     // 239
    //     name_fixed.getId()="ip"
    //     and
    //     (
    //         name_fixed.getParentNode().(Attribute).getAttr()="startswith"
    //         or
    //         name_fixed.getParentNode().getParentNode().(Call).getAnArg().(Str).getText()="127."
    //         or
    //         name_fixed.getParentNode().getParentNode().(Call).getAnArg().(Str).getText()="::ffff:7f"
    //     )
    //     and
    //     (
    //         name_fixed.getParentNode().(Compare).getAChildNode().(Str).getText()="::1"
    //         or
    //         name_fixed.getParentNode().(Compare).getAChildNode().(Str).getText()="0.0.0.0"
    //         or
    //         name_fixed.getParentNode().(Compare).getAChildNode().(Str).getText()="::"
    //     )
    // )
    // or
    // (
    //     // 240
    //     name_fixed.getId()="img"
    //     and
    //     name_fixed.getParentNode().getAChildNode().(Call).getAChildNode().(Attribute).getAttr()="get"
    //     and
    //     name_fixed.getParentNode().getAChildNode().(Call).getAChildNode().(Attribute).getAChildNode().(Name).getId()="requests"
    //     and
    //     name_fixed.getParentNode().getAChildNode().(Call).getAnArg().(Name).getId()="url"
    //     and
    //     name_fixed.getParentNode().getAChildNode().(Call).getAKeyword().getArg()="timeout"
    //     and
    //     name_fixed.getParentNode().getAChildNode().(Call).getAKeyword().getArg()="allow_redirects"
    //     and
    //     name_fixed.getParentNode().getAChildNode().(Call).getAKeyword().getValue().(Tuple).getAChildNode().(IntegerLiteral).getN().toString()="10"
    //     and
    //     name_fixed.getParentNode().getAChildNode().(Call).getAKeyword().getValue().(Tuple).getAChildNode().(IntegerLiteral).getN().toString()="200"
    //     and
    //     name_fixed.getParentNode().getAChildNode().(Call).getAKeyword().getValue().(NameConstant).getId()="False"
    //     )
    // (
    //     // 241
    //     name_fixed.getId()="csp"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Str).getText()="default-src 'self'"
    // )
    // // or
    // (
    //     // 242
    //     name_fixed.getId()="key"
    //     and
    //     name_fixed.getParentNode().(Compare).getAChildNode().(List).getAChildNode().(Str).getText()="tracks"
    //     and
    //     name_fixed.getParentNode().(Compare).getAChildNode().(List).getAChildNode().(Str).getText()="custom_tracks"
    //     and
    //     name_fixed.getParentNode().(Compare).getAChildNode().(List).getAChildNode().(Str).getText()="sample_tracks"
    //     and
    //     name_fixed.getParentNode().(Compare).getAChildNode().(List).getAChildNode().(Str).getText()="cloud_public_tracks"
    //     and
    //     name_fixed.getParentNode().(Compare).getParentNode().(If).getTest().(Compare).getAnOp().toString()="NotIn"
    //      )
    // or
    // (   
    //     // 243
    //     name_fixed.getId()="controllers"
    //     and
    //     name_fixed.getParentNode().(Attribute).getAttr()="check_session_tracks"
    //     and
    //     name_fixed.getParentNode().getParentNode().(Call).getAnArg().(Name).getId()="file_path"
    //     and
    //     name_fixed.getParentNode().getParentNode().getParentNode().(Compare).getAChildNode().(NameConstant).getId()="False"
    //     and
    //     name_fixed.getParentNode().getParentNode().getParentNode().(Compare).getAnOp().toString()="Is"
    // )
    // or
    // (
    //     // 244
    //     name_fixed.getId()="url"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Subscript).getAChildNode().(Name).getId()="images"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Subscript).getAChildNode().(IntegerLiteral).getN().toString()="0"
    // )
    // or
    // (
    //     // 245
    //     name_fixed.getId()="url"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().
    //     (Call).getAChildNode().(Attribute).getAChildNode().(Attribute).getAChildNode().
    //     (Call).getAChildNode().(Attribute).getAChildNode().(Name).getId()="recipe_xml"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().
    //     (Call).getAChildNode().(Attribute).getAChildNode().(Attribute).getAChildNode().
    //     (Call).getAChildNode().(Attribute).getAttr()="find"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().
    //     (Call).getAChildNode().(Attribute).getAChildNode().(Attribute).getAttr()="text"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().
    //     (Call).getAChildNode().(Attribute).getAttr()="strip"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().
    //     (Call).getAChildNode().(Attribute).getAChildNode().(Attribute).getAChildNode().
    //     (Call).getAnArg().(Str).getText()="imageurl"
    // )
    // or
    // (
    //     // 246
    //     name_fixed.getId()="url"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Subscript).getAChildNode().(Name).getId()="file"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Subscript).getAChildNode().(Str).getText()="originalPicture"
    // )
    // or
    // (
    //     // 247no
    // )
    // or
//     (
//         // 248
//         name_fixed.getId()="url"
//         and
//         name_fixed.getParentNode().(AssignStmt).getAChildNode().
//         (Call).getAChildNode().(Attribute).getAChildNode().(Attribute).
//         getAChildNode().(Name).getId()="recipe"
//         and
//         name_fixed.getParentNode().(AssignStmt).getAChildNode().
//         (Call).getAChildNode().(Attribute).getAChildNode().(Attribute).getAttr()="link"
//         and
//         name_fixed.getParentNode().(AssignStmt).getAChildNode().
//         (Call).getAChildNode().(Attribute).getAttr()="replace"
//     )
        // or
        // (
        //     // 249
        //     name_fixed.getId()="validators"
        //     and
        //     name_fixed.getParentNode().(Attribute).getAttr()="url"
        //     and
        //     name_fixed.getParentNode().getParentNode().(Call).getAnArg().(Name).getId()="url"
        //     and
        //     name_fixed.getParentNode().getParentNode().(Call).getAKeyword().getArg()="public"
        //     and
        //     name_fixed.getParentNode().getParentNode().(Call).getAKeyword().getValue().(NameConstant).getId()="True"
        //     and
        //     name_fixed.getParentNode().getParentNode().getParentNode() instanceof If
        // )
        // or
        // (
        //     // 250
        //     name_fixed.getId()="url"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Subscript).getAChildNode().(Str).getText()="image_url"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Subscript).getAChildNode().(Attribute).getAttr()="validated_data"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Subscript).getAChildNode().(Attribute).getAChildNode().(Name).getId()="serializer"
        // )
        // or
        // (
        //     // 251
        //     name_fixed.getId()="validators"
        //     and
        //     name_fixed.getParentNode().(Attribute).getAttr()="url"
        //     and
        //     name_fixed.getParentNode().getParentNode().(Call).getAnArg().(Name).getId()="url"
        //     and
        //     name_fixed.getParentNode().getParentNode().(Call).getAKeyword().getArg()="public"
        //     and
        //     name_fixed.getParentNode().getParentNode().(Call).getAKeyword().getValue().(NameConstant).getId()="True"
        // )
        // or
        // (
        //     // 252
        //     name_fixed.getId()="_validate_url"
        //     and
        //     name_fixed.getParentNode().(Call).getAnArg().(Name).getId()="url"
        // )

}



from Name name_fixed, Stmt stmt
where 
isFixed(name_fixed)
select name_fixed, name_fixed.getLocation()," The file is correctly fixed"