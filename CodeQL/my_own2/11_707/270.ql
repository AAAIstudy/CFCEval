
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
//  (
//     // 270_271
//     name_fixed.getId()="outputFormat"
//     and
//     name_fixed.getParentNode().(AssignStmt).getAChildNode().
//     (Call).getAChildNode().(Attribute).getAChildNode().(Name).getId()="pyRdfa"
//     and
//     name_fixed.getParentNode().(AssignStmt).getAChildNode().
//     (Call).getAChildNode().(Attribute).getAttr()="_validate_output_format"
//     and
//     name_fixed.getParentNode().(AssignStmt).getAChildNode().
//     (Call).getAnArg().(Name).getId()="outputFormat"
//  )
    // or
    // (
    //     // 272
    //     name_fixed.getId()="retval"
    //     and
    //     name_fixed.getParentNode().(BinaryExpr).getAChildNode().(BinaryExpr).
    //     getAChildNode().(Str).getText()="<dt>Media Type:</dt><dd>%s</dd>\n"
    //     and
    //     name_fixed.getParentNode().(BinaryExpr).getAChildNode().(BinaryExpr).
    //     getAChildNode().(Call).getAChildNode().(Attribute).getAttr()="escape"
    //     and
    //     name_fixed.getParentNode().(BinaryExpr).getAChildNode().(BinaryExpr).
    //     getAChildNode().(Call).getAChildNode().(Attribute).getAChildNode().(Name).getId()="cgi"
    //     and
    //     name_fixed.getParentNode().(BinaryExpr).getAChildNode().(BinaryExpr).
    //     getAChildNode().(Call).getAnArg().(Name).getId()="media_type"
    //     and
    //     name_fixed.getParentNode().(BinaryExpr).getOp().toString()="Add"
    // )
    // or
       // or
    // (
    //     // 273
    //     name_fixed.getId()="retval"
    //     and
    //     name_fixed.getParentNode().(BinaryExpr).getAChildNode().(BinaryExpr).
    //     getAChildNode().(Str).getText()="<dt>Requested graphs:</dt><dd>%s</dd>\n"
    //     and
    //     name_fixed.getParentNode().(BinaryExpr).getAChildNode().(BinaryExpr).
    //     getAChildNode().(Call).getAChildNode().(Attribute).getAttr()="escape"
    //     and
    //     name_fixed.getParentNode().(BinaryExpr).getAChildNode().(BinaryExpr).
    //     getAChildNode().(Call).getAChildNode().(Attribute).getAChildNode().(Name).getId()="cgi"
    //     and
    //     name_fixed.getParentNode().(BinaryExpr).getAChildNode().(BinaryExpr).
    //     getAChildNode().(Call).getAnArg().(Call).getAChildNode().(Attribute).getAttr()="lower"
    //     and
    //     name_fixed.getParentNode().(BinaryExpr).getAChildNode().(BinaryExpr).
    //     getAChildNode().(Call).getAnArg().(Call).getAChildNode().getAChildNode().getAChildNode().
    //     getAChildNode().(Name).getId()="form"
    //     and
    //     name_fixed.getParentNode().(BinaryExpr).getAChildNode().(BinaryExpr).
    //     getAChildNode().(Call).getAnArg().(Call).getAChildNode().getAChildNode().getAChildNode().
    //     (Attribute).getAttr()="getfirst"
    //     and
    //     name_fixed.getParentNode().(BinaryExpr).getOp().toString()="Add"
    // )
    // or
    // (
    //     // 274
    //     name_fixed.getId()="retval"
    //     and
    //     name_fixed.getParentNode().(BinaryExpr).getAChildNode().(BinaryExpr).
    //     getAChildNode().(Str).getText()="<dt>Space preserve:</dt><dd> %s</dd>\n"
    //     and
    //     name_fixed.getParentNode().(BinaryExpr).getAChildNode().(BinaryExpr).
    //     getAChildNode().(Call).getAChildNode().(Attribute).getAttr()="escape"
    //     and
    //     name_fixed.getParentNode().(BinaryExpr).getAChildNode().(BinaryExpr).
    //     getAChildNode().(Call).getAChildNode().(Attribute).getAChildNode().(Name).getId()="cgi"
    //     and
    //     name_fixed.getParentNode().(BinaryExpr).getAChildNode().(BinaryExpr).
    //     getAChildNode().(Call).getAnArg().(Attribute).getAChildNode().
    //     (Subscript).getAChildNode().(Name).getId()="form"
    //     and
    //     name_fixed.getParentNode().(BinaryExpr).getAChildNode().(BinaryExpr).
    //     getAChildNode().(Call).getAnArg().(Attribute).getAChildNode().
    //     (Subscript).getAChildNode().(Str).getText()="space_preserve"
    //     and
    //     name_fixed.getParentNode().(BinaryExpr).getAChildNode().(BinaryExpr).
    //     getAChildNode().(Call).getAnArg().(Attribute).getAttr()="value"
    // )
    // or
    // (
    //     // 275
    //     name_fixed.getId()="escape"
    //     and
    //     name_fixed.getParentNode().(Call).getAnArg().(Name).getId()="title"
    //     and
    //     name_fixed.getParentNode().(Call).getAKeyword().getArg()="quote"
    //     and
    //     name_fixed.getParentNode().(Call).getAKeyword().getValue().(NameConstant).
    //     getId()="True"
    //     and
    //     name_fixed.getParentNode().getParentNode() instanceof Return
    // )
    // or
    // (
    //     // 276
    //     name_fixed.getId()="HttpResponseBadRequest"
    //     and
    //     name_fixed.getParentNode().(Call).getAnArg().(Call).getAChildNode().(Name).getId()="htmlEscape"
    //     and
    //     name_fixed.getParentNode().(Call).getAnArg().(Call).getAnArg().(Name).getId()="msgStr"
    //     and
    //     name_fixed.getParentNode().getParentNode() instanceof Return
    // )
    // or
    (
        
    )
}



from Name name_fixed, Stmt stmt
where 
isFixed(name_fixed)
select name_fixed, name_fixed.getLocation()," The file is correctly fixed"