
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
    //     // 286
    //     name_fixed.getId()="root"
    //     and
    //     name_fixed.getParentNode().(Compare).getAnOp().getSymbol().toString()="=="
    //     and
    //     name_fixed.getParentNode().(Compare).getAChildNode().(Attribute). 
    //     getAChildNode().(Attribute). 
    //     getAChildNode().(Name).getId()="info"
    //     and
    //     name_fixed.getParentNode().(Compare).getAChildNode().(Attribute). 
    //     getAChildNode().(Attribute).getAttr()="context"
    //     and
    //     name_fixed.getParentNode().(Compare).getAChildNode().(Attribute).getAttr()="user"
    // )
    // or
    // (
    //     // 287_288
    //     name_fixed.getId()="user_profile"
    //     and
    //     name_fixed.getParentNode().(Attribute).getAttr()="is_realm_admin"
    //     and
    //     name_fixed.getParentNode().getParentNode().(UnaryExpr).getOp().toString()="Not"
    //     and
    //     name_fixed.getParentNode().getParentNode().getParentNode().(If).getBody().
    //     getAnItem().(Raise).getAChildNode().(Call).
    //     getFunc().toString()="OrganizationAdministratorRequired"
    // )
    // or
    (
        // 289_290
        name_fixed.getId()="permission_classes"
        and
        name_fixed.getParentNode().(AssignStmt).getAChildNode().(List). 
        getAChildNode().(Attribute).getAChildNode().(Name).getId()="permissions"
        and
        name_fixed.getParentNode().(AssignStmt).getAChildNode().(List). 
        getAChildNode().(Attribute).getAttr()="IsAuthenticated"
        and
        name_fixed.getParentNode().(AssignStmt).getAChildNode().(List). 
        getAChildNode().(Name).getId()="IsSuperUser"
    )

}



from Name name_fixed, Stmt stmt
where 
isFixed(name_fixed)
select name_fixed, name_fixed.getLocation()," The file is correctly fixed"
