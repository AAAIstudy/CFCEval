
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
        // 264
    // )
    // or
    // (
    //     // 265
    //     name_fixed.getId()="paths"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(List).getAChildNode().(Name).getId()="ipython_dir"
    // )
    // or
    // (
    //     // 266
    //     name_fixed.getId()="msg_obj"
    //     and
    //     name_fixed.getParentNode().(Attribute).getAttr()="channel"
    //     and
    //     name_fixed.getParentNode().getParentNode().(Attribute).getAttr()="permissions_for"
    //     and
    //     name_fixed.getParentNode().getParentNode().getParentNode().(Call).getAnArg().(Name).getId()="issuer"
    //     and
    //     name_fixed.getParentNode().getParentNode().getParentNode().getParentNode().(Attribute).getAttr()="view_channel"
    //     and
    //     name_fixed.getParentNode().getParentNode().getParentNode().getParentNode().getParentNode().(Compare).getAChildNode().(NameConstant).getId()="False"
    //     and
    //     name_fixed.getParentNode().getParentNode().getParentNode().getParentNode().getParentNode().getParentNode() instanceof If
    //     and 
    //     name_fixed.getParentNode().getParentNode().getParentNode().getParentNode().getParentNode().getParentNode().(If).getBody().getAnItem() instanceof Raise
    // )
    // or
    // (
    //     // 269
    //     name_fixed.getId()="run_as_real_user"
    //     and
    //     name_fixed.getParentNode().(Call).getAKeyword().getArg()="get_user_env"
    //     and
    //     name_fixed.getParentNode().(Call).getAnArg().(List).getAChildNode().(Str).getText()="xdg-open"
    //     and
    //     name_fixed.getParentNode().(Call).getAnArg().(List).getAChildNode().(Name).getId()="url"
    //     and
    //     name_fixed.getParentNode().(Call).getAKeyword().getValue().(NameConstant).getId()="True"
    // )
    // or
    (

    )
}



from Name name_fixed, Stmt stmt
where 
isFixed(name_fixed)
select name_fixed, name_fixed.getLocation()," The file is correctly fixed"