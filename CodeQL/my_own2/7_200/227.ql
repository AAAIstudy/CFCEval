
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
    //     // 227 not working_cannot use codeql
    //     name_fixed.getId()="thread_users"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).
    //     getAChildNode().(Call).getAChildNode().(Attribute).
    //     getAChildNode().(Call).getAChildNode().(Attribute).
    //     getAChildNode().(Call).getAChildNode().(Attribute).
    //     getAChildNode().(Call).getAChildNode().(Attribute).
    //     getAChildNode().(Attribute).getAChildNode().(Call).getAChildNode().(Name).getId()="get_user_model"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).
    //     getAChildNode().(Call).getAChildNode().(Attribute).
    //     getAChildNode().(Call).getAChildNode().(Attribute).
    //     getAChildNode().(Call).getAChildNode().(Attribute).
    //     getAChildNode().(Call).getAChildNode().(Attribute).
    //     getAChildNode().(Attribute).getAttr()="objects"
    //     // and
    //     // name_fixed.getParentNode().(AssignStmt).
    //     // getAChildNode().(Call).getAChildNode().(Attribute).
    //     // getAChildNode().(Call).getAChildNode().(Attribute).
    //     // getAChildNode().(Call).getAChildNode().(Attribute).
    //     // getAChildNode().(Call).getAChildNode().(Attribute).getAttr()="exclude"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).
    //     getAChildNode().(Call).getAChildNode().(Attribute).
    //     getAChildNode().(Call).getAChildNode().(Attribute).
    //     getAChildNode().(Call).getAChildNode().(Attribute).getAttr()="exclude"
    //     // and
    //     // name_fixed.getParentNode().(AssignStmt).
    //     // getAChildNode().(Call).getAChildNode().(Attribute).
    //     // getAChildNode().(Call).getAChildNode().(Attribute).getAttr()="filter"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).
    //     getAChildNode().(Call).getAChildNode().(Attribute).getAttr()="prefetch_related"
    // )
    // or
    // (
    //     // 228
    //     name_fixed.getId()="redirect_request"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAChildNode().(Name).getId()="_build_redirect_request"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAnArg().(Name).getId()="request"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAKeyword().getArg()="url"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAKeyword().getArg()="method"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAKeyword().getArg()="body"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAKeyword().getValue().(Str).getText()="GET"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAKeyword().getValue().(Str).getText()=""
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAKeyword().getValue().(Name).getId()="redirect_url"
    // )
    // or
    // (
    //     // 229
    //     name_fixed.getId()="redirected"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAChildNode().(Name).getId()="_build_redirect_request"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAnArg().(Name).getId()="request"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAKeyword().getArg()="url"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAKeyword().getValue().(Name).getId()="redirected_url"
    // )
    // or
    // (
    //     // 230
    //     name_fixed.getId()="httpie_session"
    //     and
    //     name_fixed.getParentNode().(Attribute).getAttr()="remove_cookies"
    //     and
    //     name_fixed.getParentNode().getParentNode().(Call).getArg(0).(Name).getId()="expired_cookies"
    // )
    // or
    // (
    //     // 231
    //     name_fixed.getId()="self"
    //     and
    //     name_fixed.getParentNode().(Attribute).getAttr()="cookie_jar"
    //     and
    //     name_fixed.getParentNode().getParentNode().(Attribute).getAttr()="clear_expired_cookies"
    // )
    

}



from Name name_fixed, Stmt stmt
where 
isFixed(name_fixed)
select name_fixed, name_fixed.getLocation()," The file is correctly fixed"