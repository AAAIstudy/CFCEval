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
    //     // 97
    //     name_fixed.getId()="mtls_cert"
    //     and
    //     name_fixed.getParentNode().getAChildNode().(Subscript).getAChildNode().(Name).getId()="agent_data"
    //     and
    //     name_fixed.getParentNode().getAChildNode().(Subscript).getAChildNode().(Str).getText()="mtls_cert"
    // )
    // or
    // (
    //     // 98
    //     name_fixed.getId()="ragged_rank"
    //     and
    //     name_fixed.getParentNode().(Compare).getAChildNode().(NameConstant).getId()="None"
    //     and
    //     name_fixed.getParentNode().getParentNode().(BoolExpr).getAChildNode().(Compare).getAChildNode().(Name).getId()="max_depth"
    //     and
    //     name_fixed.getParentNode().getParentNode().(BoolExpr).getAChildNode().(Compare).getAChildNode().(Name).getId()="ragged_rank"
    //     and
    //     name_fixed.getParentNode().getParentNode().getParentNode() instanceof If
    //     and
    //     name_fixed.getParentNode().getParentNode().getParentNode().(If).getBody().getAnItem().(Raise).getAChildNode().(Call).getAChildNode().(Name).getId()="ValueError"
    //     )
    // or
    // (
    //     name_fixed.getId()="upload"
    //     and
    //     name_fixed.getParentNode().(Attribute).getAttr()="content"
    //     and
    //     name_fixed.getParentNode().(Attribute).getParentNode().(Attribute).getAttr()="open"
    //     and
    //     name_fixed.getParentNode().getParentNode().getParentNode().(Call).getParentNode().(With).getAChildNode().(Name).getId()="content"
    //     and
    //     name_fixed.getParentNode().getParentNode().getParentNode().(Call).getArg(0).(Str).getText()="rb"
    // )
    // or
    // (
    //     // 101
    //     (
    //         name_fixed.getId()="file_content" or name_fixed.getId()="file_path"
    //     )
    //     and
    //     (
    //         name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAChildNode().(Name).getId()="_try_read"
    //         or
    //         name_fixed.getParentNode().(AssignStmt).getAChildNode().(IfExp).getAChildNode().(Name).getId()="file_content"
    //     )
    // )
    // or
    // (
    //         // 106 not parserd    
    // )
    // or
    // (
    //     // 107_108
    //     name_fixed.getId()="tasks"
    //     and
    //     name_fixed.getParentNode().(UnaryExpr).getParentNode().(BoolExpr).getAChildNode().(UnaryExpr).getAChildNode().(Compare).getAChildNode().(Attribute).getAttr()="status"
    //     and
    //     name_fixed.getParentNode().(UnaryExpr).getParentNode().(BoolExpr).getAChildNode().(UnaryExpr).getAChildNode().(Compare).getAChildNode().(Attribute).getAttr()="NOTAPPLICABLE"
    // )
    // or
    // (
    //     // 109
    //     name_fixed.getId()="default_value"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Name).getId()="value"
    //     and
    //     name_fixed.getParentNode().getParentNode().getAChildNode().(If).getAChildNode().(Compare).getAChildNode().(Str).getText()=":"
    //     and
    //     name_fixed.getParentNode().getParentNode().getAChildNode().(If).getAChildNode().(Compare).getAChildNode().(Name).getId()="value"
    // )
    // or
    // (
    //     (
    //         // 110
    //         (name_fixed.getId()="hours" or name_fixed.getId()="seconds")
    //         and
    //         name_fixed.getParentNode().getParentNode().getAChildNode().(Call).getAChildNode().(Attribute).getAttr()="split"
    //         and
    //         name_fixed.getParentNode().getParentNode().getAChildNode().(Call).getAChildNode().(Attribute).getAChildNode().(Name).getId()="value"
    //     )
    // )
    // or
    // (
    //     // 111
    //     name_fixed.getId()="value"
    //     and
    //     name_fixed.getParentNode().getParentNode().getParentNode() instanceof Return
    //     and
    //     name_fixed.getParentNode().getAChildNode().(Tuple).getAChildNode().(NameConstant).getId()="None"
    //     and
    //     name_fixed.getParentNode().getParentNode().(IfExp).getAChildNode().(Call).getAChildNode().(Attribute).getAttr()="realpath"
    //     and
    //     name_fixed.getParentNode().getParentNode().(IfExp).getAChildNode().(Call).getAChildNode().(Attribute).getAChildNode().(Attribute).getAttr()="path"
    //     and
    //     name_fixed.getParentNode().getParentNode().getParentNode() instanceof Return
    //     )
    // or
    // (
    //     // 113
    //     name_fixed.getId()="kwargs"
    //     and
    //     name_fixed.getParentNode().getAChildNode().(Str).getText()="url_fetcher"
    //     and
    //     name_fixed.getParentNode().getParentNode().getAChildNode().(UnaryExpr).getAChildNode().(Name).getId()="unsafe"
    // )

}


from Name name_fixed, Stmt stmt
where 
isFixed(name_fixed)
select name_fixed, name_fixed.getLocation()," The file is correctly fixed"

