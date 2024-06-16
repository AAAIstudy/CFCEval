
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
    // // 167
    // name_fixed.getId()="delete_form"
    // and
    // name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAChildNode().(Name).getId()="DeleteSshForm"
    // )
    // or
    // (
    //     // 168
    //     name_fixed.getId()="action"
    //     and
    //     name_fixed.getParentNode().getAChildNode().(Str).getText()="delete"
    //     and
    //     name_fixed.getParentNode().getParentNode().(BoolExpr).getAChildNode().(Call).getAChildNode().(Attribute).getAttr()="is_submitted"
    //     and
    //     name_fixed.getParentNode().getParentNode().(BoolExpr).getAChildNode().(Call).getAChildNode().(Attribute).getAChildNode().(Name).getId()="delete_form"
    // )
    // or
    // (
    //     // 169
    //     name_fixed.getId()="DeleteUserForm" 
    //     and
    //     name_fixed.getParentNode().getParentNode().(AssignStmt).getAChildNode().(Name).getId()="form"
    //     // and
    //     // name_fixed.getParentNode().getParentNode().getParentNode().(If).getBody().getAnItem().(If).getAChildNode().(Call).getAChildNode().(Attribute).getAttr()="validate_on_submit"
    // )
    // or
    // (
    //     // 170
    //     name_fixed.getId()="StringField"
    //     and
    //     name_fixed.getParentNode().getParentNode().(AssignStmt).getAChildNode().(Name).getId()="confirm"
    //     and
    //     name_fixed.getParentNode().(Call).getAnArg().(Call).getAChildNode().(Name).getId()="_"
    //     and
    //     name_fixed.getParentNode().(Call).getAKeyword().getArg()="validators"
    //     and
    //     name_fixed.getParentNode().(Call).getAKeyword().getValue().(List).getAChildNode().(Call).getAChildNode().(Name).getId()="DataRequired"
    // )
    // or
    // (
        // 171
    //     name_fixed.getId()="cherrypy"
    //     and
    //     name_fixed.getParentNode().(Attribute).getAttr()="request"
    //     and
    //     name_fixed.getParentNode().(Attribute).getParentNode().(Attribute).getAttr()="method"
    //     and
    //     name_fixed.getParentNode().getParentNode().getParentNode().(Compare).getAChildNode().(Str).getText()="POST"
    //     and
    //     name_fixed.getParentNode().getParentNode().getParentNode().getParentNode().(BoolExpr).getAChildNode().(Compare).getAChildNode().(Name).getId()="action"
    //     and
    //     name_fixed.getParentNode().getParentNode().getParentNode().getParentNode().(BoolExpr).getAChildNode().(Compare).getAChildNode().(Str).getText()="set_notification_info"
    // )
    // or
    // (
    //     // 172_173
    //     name_fixed.getId()="cherrypy"
    //     and
    //     name_fixed.getParentNode().(Attribute).getAttr()="request"
    //     and
    //     name_fixed.getParentNode().getParentNode().(Attribute).getAttr()="method"
    //     and
    //     name_fixed.getParentNode().getParentNode().getParentNode().(Compare).getAChildNode().(Str).getText()="POST"
    //     and
    //     name_fixed.getParentNode().getParentNode().getParentNode().(Compare).getAnOp().getSymbol()="=="
    // )
    // or
    // (
    //     // 174
    //     name_fixed.getId()="resp"
    //     and
    //     name_fixed.getParentNode().(Attribute).getAttr()="set_cookie"
    //     and
    //     (
    //     name_fixed.getParentNode().getParentNode().(Call).getArg(0).(Str).getText()="auth_token"
    //     or
    //     name_fixed.getParentNode().getParentNode().(Call).getArg(0).(Str).getText()="auth_username"
    //     )
    //     and
    //     name_fixed.getParentNode().getParentNode().(Call).getAKeyword().getArg()="samesite"
    //     and
    //     name_fixed.getParentNode().getParentNode().(Call).getAKeyword().getValue().(Str).getText()="Lax"
    // )
    // or
    // (
    //     // 175
    //     name_fixed.getId()="resp"
    //     and
    //     name_fixed.getParentNode().(Attribute).getAttr()="set_cookie"
    //     and
    //     (
    //     name_fixed.getParentNode().getParentNode().(Call).getArg(0).(Str).getText()="auth_token"
    //     or
    //     name_fixed.getParentNode().getParentNode().(Call).getArg(0).(Str).getText()="auth_username"
    //     )
    //     and
    //     (
    //         name_fixed.getParentNode().getParentNode().(Call).getArg(1).(Attribute).getAttr()="token"
    //         or
    //         name_fixed.getParentNode().getParentNode().(Call).getArg(1).(Name).getId()="username"
    //     )
    //     and
    //     name_fixed.getParentNode().getParentNode().(Call).getAKeyword().getArg()="samesite"
    //     and
    //     name_fixed.getParentNode().getParentNode().(Call).getAKeyword().getValue().(Str).getText()="Lax"
    // )
    // or
    // (
    //     // 176
    //     name_fixed.getId()="request"
    //     and
    //     name_fixed.getParentNode().(Attribute).getAttr()="method"
    //     and
    //     name_fixed.getParentNode().getParentNode().(Compare).getAnOp().getSymbol()="!="
    //     and
    //     name_fixed.getParentNode().getParentNode().(Compare).getAChildNode().(Str).getText()="POST"
    //     and
    //     name_fixed.getParentNode().getParentNode().getParentNode().(If).getBody().getAnItem().(Raise).getAChildNode().(Call).getAChildNode().(Attribute).getAttr()="HTTPError"
    //     and
    //     name_fixed.getParentNode().getParentNode().getParentNode().(If).getBody().getAnItem().(Raise).getAChildNode().(Call).getAChildNode().(Attribute).getAChildNode().(Name).getId()="cherrypy"
    //     and
    //     name_fixed.getParentNode().getParentNode().getParentNode().(If).getBody().getAnItem().(Raise).getAChildNode().(Call).getAnArg().(IntegerLiteral).getN().toString()="405"
    // )
    // or
    // (
    //     // 177_178_180
    //     name_fixed.getId()="require_http_methods"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(0).(List).getAChildNode().(Str).getText()="POST"
    // )
    // or
    // (
    //     // 179
    //     name_fixed.getId()="require_http_methods"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(0).(List).getAChildNode().(Str).getText()="DELETE"
    // )
    // or
    // (
    //     // 181 not parserd
    // )

}



from Name name_fixed, Stmt stmt
where 
isFixed(name_fixed)
select name_fixed, name_fixed.getLocation()," The file is correctly fixed"
