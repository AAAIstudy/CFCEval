
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
    //     // 280
    //     name_fixed.getId()="password"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getFunc().toString()="PasswordField"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAKeyword().getArg()="validators"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAnArg().(Call).getFunc().toString()="_"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAnArg().(Call).getAnArg().(Str).getText()="Password"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAKeyword().getValue().
    //     (List).getAChildNode().(Call).getAChildNode().(Attribute).getAChildNode().(Name).
    //     getId()="validators"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAKeyword().getValue().
    //     (List).getAChildNode().(Call).getAChildNode().(Attribute).getAttr()="optional"
    // )
    // or
    // (
    //      // 281_282
    //      name_fixed.getId()="cfg"
    //      and
    //      name_fixed.getParentNode().getAChildNode().(Attribute).getAttr()="cfg"
    //      and
    //      name_fixed.getParentNode().getAChildNode().getAChildNode().(Attribute).getAttr()="app"
    //      and
    //      name_fixed.getParentNode().getAChildNode().getAChildNode().getAChildNode().(Attribute).getAttr()="_store"
    //      and
    //      name_fixed.getParentNode().getAChildNode().getAChildNode().getAChildNode().getAChildNode().(Name).getId()="self"
    // )
    // or
    // (
    //     // 283
    //     name_fixed.getId()="password_form"
    //     and
    //     name_fixed.getParentNode().(Attribute).getAttr()="populate_obj"
    //     and
    //     name_fixed.getParentNode().getParentNode().(Call).getAnArg().
    //     (Attribute).getAChildNode().(Attribute).
    //     getAChildNode().(Name).getId()="self"
    //     and
    //     name_fixed.getParentNode().getParentNode().(Call).getAnArg().
    //     (Attribute).getAChildNode().(Attribute).getAttr()="app"
    //     and
    //     name_fixed.getParentNode().getParentNode().(Call).getAnArg().
    //     (Attribute).getAttr()="currentuser"
    // )
    // or
    // (
    //     // 284
    //    ( name_fixed.getId()="newpassword"
    //     or
    //     name_fixed.getId()="confirmation")
    //     and
    //     name_fixed.getParentNode().(BoolExpr).getParentNode() instanceof If
    //     and
    //     name_fixed.getParentNode().(BoolExpr).getParentNode().(If).
    //     getElif().getAChildNode().(If).getAChildNode().(UnaryExpr).
    //     getAChildNode().(Name).getId()="confirmation"
    // )
    // or
    (
        // 285
        name_fixed.getId()="self"
        and
        name_fixed.getParentNode().(Attribute).getAttr()="current"
        and
        name_fixed.getParentNode().getParentNode().(Attribute).getAttr()="errors"
        and
        name_fixed.getParentNode().getParentNode().getParentNode().(AssignStmt).
        getAChildNode().(List).getAChildNode().(Call).getFunc().toString()="_"
        and
        name_fixed.getParentNode().getParentNode().getParentNode().(AssignStmt).
        getAChildNode().(List).getAChildNode().(Call).getAnArg().
        (Str).getText()="Wrong current password."
    )
   


}



from Name name_fixed, Stmt stmt
where 
isFixed(name_fixed)
select name_fixed, name_fixed.getLocation()," The file is correctly fixed"