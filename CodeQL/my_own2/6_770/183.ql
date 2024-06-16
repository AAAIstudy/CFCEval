
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
    //     // 183_184_188_189
    //     name_fixed.getId()="validators"
    //     and
    //     name_fixed.getParentNode().(Attribute).getAttr()="length"
    //     and
    //     (
    //         name_fixed.getParentNode().getParentNode().(Call).getAKeyword().getArg()="max"
    //         or
    //         name_fixed.getParentNode().getParentNode().(Call).getAKeyword().getArg()="message"
    //     )
       
    //     and
    //     (
    //         name_fixed.getParentNode().getParentNode().(Call).getAKeyword().getValue().(IntegerLiteral).getN().toString()="256"
    //         or
    //         name_fixed.getParentNode().getParentNode().(Call).getAKeyword().getValue().(Name).getId()="MAX_PATH"
    //         or
    //         name_fixed.getParentNode().getParentNode().(Call).getAKeyword().getValue().(Call).getArg(0).(Str).getText()="Username too long."
    //         or
    //         name_fixed.getParentNode().getParentNode().(Call).getAKeyword().getValue().(Call).getArg(0).(Str).getText()="Fullname too long."
    //         or
    //         name_fixed.getParentNode().getParentNode().(Call).getAKeyword().getValue().(Call).getArg(0).(Str).getText()="Title too long."
    //         or
    //         name_fixed.getParentNode().getParentNode().(Call).getAKeyword().getValue().(Call).getArg(0).(Str).getText()="Fullname too long."
    //         )
    //     and
    //     name_fixed.getParentNode().getParentNode().(Call).getAKeyword().getValue().(Call).getAChildNode().(Name).getId()="_"
    // )
    // or
    // (
    //     // 185
    //     name_fixed.getId()="InputRequired"
    //     and
    //     name_fixed.getParentNode().(Call).getParentNode().(List).getAnElt().(Call).getAChildNode().(Name).getId()="Length"
    //     and
    //     name_fixed.getParentNode().(Call).getParentNode().(List).getAnElt().(Call).getAKeyword().getArg()="max"
    //     and
    //     name_fixed.getParentNode().(Call).getParentNode().(List).getAnElt().(Call).getAKeyword().getArg()="message"
    //     and
    //     name_fixed.getParentNode().(Call).getParentNode().(List).getAnElt().(Call).getAKeyword().getValue().(IntegerLiteral).getN().toString()="256"
    //     and
    //     name_fixed.getParentNode().(Call).getParentNode().(List).getAnElt().(Call).getAKeyword().getValue().(Call).getFunc().toString()="_"
    //     and
    //     name_fixed.getParentNode().(Call).getParentNode().(List).getAnElt().(Call).getAKeyword().getValue().(Call).getAnArg().(Str).getText()="Username too long."
    // )
    // or
//     (
//         // 186
//         name_fixed.getId()="Length"
//         and
//         name_fixed.getParentNode().(Call).getAKeyword().getArg()="max"
//         and
//         name_fixed.getParentNode().(Call).getAKeyword().getArg()="message"
//         and
//         name_fixed.getParentNode().(Call).getAKeyword().getValue().(Call).getFunc().toString()="_"
//         and
//         name_fixed.getParentNode().(Call).getAKeyword().getValue().(Call).getAnArg().(Str).getText()="Invalid email."
//     )
// or
        // (
        //     // 187_no
        // )
        // or 
        // (
        //     // 190
        //     name_fixed.getId()="Length"
        //     and
        //     name_fixed.getParentNode().(Call).getParentNode().(List).getParentNode().(Keyword).getParentNode().(Call).getFunc().toString()="StringField"
        //     and
        //     name_fixed.getParentNode().(Call).getParentNode().(List).getAChildNode().(Call).getFunc().toString()="Optional"
        //     and
        //     name_fixed.getParentNode().(Call).getAKeyword().getArg()="max"
        //     and
        //     name_fixed.getParentNode().(Call).getAKeyword().getArg()="message"
        //     and
        //     name_fixed.getParentNode().(Call).getAKeyword().getValue().(IntegerLiteral).getN().toString()="256"
        //     and
        //     name_fixed.getParentNode().(Call).getAKeyword().getValue().(Call).getAnArg().(Str).getText()="Fullname too long."
        //     and
        //     name_fixed.getParentNode().(Call).getAKeyword().getValue().(Call).getFunc().toString()="_"
        //     )
        // or
        // (
        //     // 191
        //     name_fixed.getId()="Length"
        //     and
        //     name_fixed.getParentNode().(Call).getParentNode().(List).getParentNode().(Keyword).getParentNode().(Call).getFunc().toString()="StringField"
        //     and
        //     name_fixed.getParentNode().(Call).getParentNode().(List).getAChildNode().(Call).getFunc().toString()="DataRequired"
        //     and
        //     name_fixed.getParentNode().(Call).getAKeyword().getArg()="max"
        //     and
        //     name_fixed.getParentNode().(Call).getAKeyword().getArg()="message"
        //     and
        //     name_fixed.getParentNode().(Call).getAKeyword().getValue().(IntegerLiteral).getN().toString()="256"
        //     and
        //     name_fixed.getParentNode().(Call).getAKeyword().getValue().(Call).getAnArg().(Str).getText()="Token name too long"
        //     and
        //     name_fixed.getParentNode().(Call).getAKeyword().getValue().(Call).getFunc().toString()="_"
        // )
        // or
        // (
        //         // 194
        //         name_fixed.getId()="valid"
        //         and
        //         name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getFunc().toString()="any"
        //         and
        //         name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAnArg().(Call).getAChildNode().(Attribute).getAttr()="publish"
        //         and
        //         name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAnArg().(Call).getAChildNode().getAChildNode().(Attribute).getAttr()="engine"
        //         and
        //         name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAnArg().(Call).getAChildNode().getAChildNode().getAChildNode().(Name).getId()="cherrypy"
        //         and
        //         name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAnArg().(Call).getAnArg().(Str).getText()="login"
        //         and
        //         name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAnArg().(Call).getAnArg().(Name).getId()="username"
        //         and
        //         name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAnArg().(Call).getAnArg().(Name).getId()="password"
        // )
        // or
        // (
        //     // 195
        //     name_fixed.getId()="cherrypy"
        //     and
        //     name_fixed.getParentNode().(Attribute).getAttr()="tools"
        //     and
        //     (
        //     name_fixed.getParentNode().(Attribute).getParentNode().(Attribute).getAttr()="ratelimit"
        //     or
        //     name_fixed.getParentNode().(Attribute).getParentNode().(Attribute).getAttr()="sessions"
        //     )
        //     and
        //     (
        //     name_fixed.getParentNode().getParentNode().getParentNode().(Call).getAKeyword().getArg()="scope"
        //     or
        //     name_fixed.getParentNode().getParentNode().getParentNode().(Call).getAKeyword().getArg()="hit"
        //     or
        //     name_fixed.getParentNode().getParentNode().getParentNode().(Call).getAKeyword().getArg()="priority"
        //     or
        //     name_fixed.getParentNode().getParentNode().getParentNode().(Call).getAKeyword().getArg()="on"
        //     )
        //     and
        //     (
        //     name_fixed.getParentNode().getParentNode().getParentNode().(Call).getAKeyword().getValue().(IntegerLiteral).getN().toString()="0"
        //     or
        //     name_fixed.getParentNode().getParentNode().getParentNode().(Call).getAKeyword().getValue().(IntegerLiteral).getN().toString()="69"
        //     or
        //     name_fixed.getParentNode().getParentNode().getParentNode().(Call).getAKeyword().getValue().(Str).getText()="rdiffweb-api"
        //     or
        //     name_fixed.getParentNode().getParentNode().getParentNode().(Call).getAKeyword().getValue().(NameConstant).getId()="False"
        //     )
        // )
        // or
        // (
        //     // 196_197__206
        //     name_fixed.getId()="cherrypy"
        //     and
        //     name_fixed.getParentNode().(Attribute).getAttr()="tools"
        //     and
        //     name_fixed.getParentNode().(Attribute).getParentNode().(Attribute).getAttr()="ratelimit"
        //     and
        //     name_fixed.getParentNode().getParentNode().getParentNode().(Call).getAKeyword().getArg()="methods"
        //     and
        //     name_fixed.getParentNode().getParentNode().getParentNode().(Call).getAKeyword().getValue().(List).getAChildNode().(Str).getText()="POST"
        //     )
        // or
        // (
        //     // 198
        //     name_fixed.getId()="cherrypy"
        //     and
        //     name_fixed.getParentNode().(Attribute).getAttr()="tools"
        //     and
        //     name_fixed.getParentNode().(Attribute).getParentNode().(Attribute).getAttr()="ratelimit"
        //     and
        //     name_fixed.getParentNode().getParentNode().getParentNode().(Call).getAKeyword().getArg()="methods"
        //     and
        //     name_fixed.getParentNode().getParentNode().getParentNode().(Call).getAKeyword().getArg()="logout"
        //     and
        //     name_fixed.getParentNode().getParentNode().getParentNode().(Call).getAKeyword().getValue().(List).getAChildNode().(Str).getText()="POST"
        //     and
        //     name_fixed.getParentNode().getParentNode().getParentNode().(Call).getAKeyword().getValue().(NameConstant).getId()="True"
        // )
        // or
        // (
        //     // 200
        //     name_fixed.getId()="limit"
        //     and
        //     name_fixed.getParentNode().(Compare).getAnOp().getSymbol()="<="
        //     and
        //     name_fixed.getParentNode().(Compare).getAChildNode().(IntegerLiteral).getN().toString()="0"
        //     and
        //     name_fixed.getParentNode().getParentNode().(If).getBody().getAnItem() instanceof Return
        // )
        //or
        // (
        //     // 202
        //     name_fixed.getId()="hits"
        //     and 
        //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAChildNode().(Attribute).getAChildNode().(Name).getId()="datastore"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAChildNode().(Attribute).getAttr()="get_and_increment"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAnArg().(Name).getId()="token"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAnArg().(Name).getId()="delay"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAnArg().(Name).getId()="hit"
        // )
        // or
        // (
        //     // 203
        //     name_fixed.getId()="request"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Attribute).getAttr()="request"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Attribute).getAChildNode().(Name).getId()="cherrypy"
        // )
        // or
        // (
        //     // 208
        //     name_fixed.getId()="self"
        //     and
        //     name_fixed.getParentNode().(Attribute).getAttr()="_parts_decoded"
        //     and
        //     name_fixed.getParentNode().getParentNode().(BinaryExpr).getAChildNode().(IntegerLiteral).getN().toString()="1"
        // )
        // or
        // (
        // // 210_213
        //     name_fixed.getId()="self"
        //     and
        //     name_fixed.getParentNode().(Attribute).getAttr()="max_form_parts"
        //     and
        //     name_fixed.getParentNode().getParentNode().(AssignStmt).getAChildNode().(Name).getId()="max_form_parts"
        // )
        // or
        // (
        //     // 214
        //     name_fixed.getId()="MultipartDecoder"
        //     and
        //     name_fixed.getParentNode().getParentNode().getAChildNode().(Name).getId()="parser"
        //     and
        //     name_fixed.getParentNode().(Call).getAnArg().(Name).getId()="boundary"
        //     and
        //     name_fixed.getParentNode().(Call).getAnArg().(Attribute).getAttr()="max_form_memory_size"
        //     and
        //     name_fixed.getParentNode().(Call).getAKeyword().getArg()="max_parts"
        //     and
        //     name_fixed.getParentNode().(Call).getAKeyword().getValue().(Attribute).getAttr()="max_form_parts"
        // )
        // 216
        // (
        //     name_fixed.getId()="self"
        //     and
        //     name_fixed.getParentNode().(Attribute).getAttr()="max_parts"
        //     and
        //     name_fixed.getParentNode().getParentNode().(AssignStmt).getAChildNode().(Name).getId()="max_parts"
        // )
        // or
        // (
        //     // (217
        //         name_fixed.getId()="self"
        //         and
        //         name_fixed.getParentNode().(Attribute).getAttr()="_parts_decoded"
        //         and
        //         name_fixed.getParentNode().getParentNode().(AssignStmt).getAChildNode().(IntegerLiteral).getN().toString()="0"
        // )
        // or
        // (
        //     // 220
        //     name_fixed.getId()="parse_multipart_form"
        //     and
        //     name_fixed.getParentNode().(Call).getAKeyword().getArg()="body"
        //     and
        //     name_fixed.getParentNode().(Call).getAKeyword().getAChildNode().(Await).getAChildNode().(Call).getAChildNode().(Attribute).getAttr()="body"
        //     and
        //     name_fixed.getParentNode().(Call).getAKeyword().getAChildNode().(Await).getAChildNode().(Call).getAChildNode().(Attribute).getAChildNode().(Name).getId()="self"
        //     // and
        //     // name_fixed.getParentNode().(Call).getAKeyword().getArg()="boundary"
        //     // and
        // )
        // or 
        // (
        //     // 221
        //     name_fixed.getId()="body_kwarg_multipart_form_part_limit"
        //     and
        //     name_fixed.getParentNode().(AnnAssign).getAChildNode().(Subscript).getAChildNode().(Name).getId()="Optional"
        //     and
        //     name_fixed.getParentNode().(AnnAssign).getAChildNode().(Subscript).getAChildNode().(Name).getId()="int"
        //     and
        //     name_fixed.getParentNode().(AnnAssign).getAChildNode().(NameConstant).getId()="None"
        // )
        // or
        // (
        //     // 222
        //     name_fixed.getId()="multipart_form_part_limit"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(IfExp).getAChildNode().(Name).getId()="body_kwarg_multipart_form_part_limit"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(IfExp).getAChildNode().(Compare).getAChildNode().(Name).getId()="body_kwarg_multipart_form_part_limit"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(IfExp).getAChildNode().(Compare).getAChildNode().(NameConstant).getId()="None"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(IfExp).getAChildNode().(Attribute).getAChildNode().(Attribute).getAChildNode().(Name).getId()="connection"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(IfExp).getAChildNode().(Attribute).getAChildNode().(Attribute).getAttr()="app"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(IfExp).getAChildNode().(Attribute).getAttr()="app.multipart_form_part_limit"
        // )
        // or
        // (
        //     // 223
        //     name_fixed.getId()="connection"
        //     and
        //     name_fixed.getParentNode().(Attribute).getAttr()="body"
        //     and
        //     name_fixed.getParentNode().(Attribute).getParentNode().(Call).getParentNode() instanceof Await
        //     and
        //     name_fixed.getParentNode().(Attribute).getParentNode().(Call).getParentNode().(Await).getParentNode().(Keyword).getArg()="body"
        //     and
        //     name_fixed.getParentNode().getParentNode().getParentNode().getParentNode().(Keyword).getParentNode().(Call).getFunc().toString()="parse_multipart_form"
        //     and
        //     name_fixed.getParentNode().getParentNode().getParentNode().getParentNode().getParentNode().(Call).getAKeyword().getArg()="boundary"
        //     and
        //     name_fixed.getParentNode().getParentNode().getParentNode().getParentNode().getParentNode().(Call).getAKeyword().getArg()="multipart_form_part_limit"
        //     and
        //     name_fixed.getParentNode().getParentNode().getParentNode().getParentNode().getParentNode().(Call).getAKeyword().getAChildNode().(Name).getId()="multipart_form_part_limit"
        //     and
        //     name_fixed.getParentNode().getParentNode().getParentNode().getParentNode().getParentNode().(Call).getAKeyword().getAChildNode().(Call).getAChildNode().(Attribute).getAttr()="encode"
        //     )
            // or
            (
                // 226
                name_fixed.getId()="multipart_form_part_limit"
                and
                name_fixed.getParentNode().(Keyword).getArg()="multipart_form_part_limit"

            )
    }



from Name name_fixed, Stmt stmt
where 
isFixed(name_fixed)
select name_fixed, name_fixed.getLocation()," The file is correctly fixed"