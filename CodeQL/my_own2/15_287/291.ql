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
    //     // 291
    //     name_fixed.getId()="self"
    //     and
    //     name_fixed.getParentNode().(Attribute).getAttr()="select_security_type"
    //     and
    //     name_fixed.getParentNode().getParentNode().getParentNode() instanceof Return
    // )
    // or
    // (
    //     // 292_NOT HERE
    // )
    // or
    // (
    //     // 293
    //     name_fixed.getId()="key_request"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().
    //     (Call).getAChildNode().(Attribute).getAChildNode().
    //     (Attribute).getAChildNode().(Name).getId()="self"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().
    //     (Call).getAChildNode().(Attribute).getAChildNode().
    //     (Attribute).getAttr()="outgoing_key_requests"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().
    //     (Call).getAChildNode().(Attribute).getAttr()="pop"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().
    //     (Call).getAnArg().(Attribute).getAChildNode().(Name).getId()="event"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().
    //     (Call).getAnArg().(Attribute).getAttr()="session_id"
    // )



}



from Name name_fixed, Stmt stmt
where 
isFixed(name_fixed)
select name_fixed, name_fixed.getLocation()," The file is correctly fixed"