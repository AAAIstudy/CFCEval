
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
//     // 253
//     name_fixed.getId()="agent"
//     and
//     name_fixed.getParentNode().(Subscript).getAChildNode().(Str).getText()="supported_version"
//     and
//     name_fixed.getParentNode().(Subscript).getParentNode().(Compare).getAChildNode().(Str).getText()="1.0"
//     and
//     name_fixed.getParentNode().(Subscript).getParentNode().(Compare).getParentNode().(Keyword).getArg()="compressed"
//     and
//     name_fixed.getParentNode().(Subscript).getParentNode().(Compare).getAnOp().getSymbol()="=="
//     )
//     or
    // (
    //     // 254
    //     name_fixed.getId()="failure"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().
    //     (Call).getAChildNode().(Attribute).getAChildNode().(Attribute).
    //     getAChildNode().(Name).getId()="self"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().
    //     (Call).getAChildNode().(Attribute).getAChildNode().(Attribute).getAttr()="tpm_instance"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().
    //     (Call).getAChildNode().(Attribute).getAttr()="check_quote"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().
    //     (Call).getAnArg().(Call).getAChildNode().(Name).getId()="AgentAttestState"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().
    //     (Call).getAnArg().(Name).getId()="public_key"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().
    //     (Call).getAnArg().(Name).getId()="quote"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().
    //     (Call).getAKeyword().getArg()="hash_alg"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().
    //     (Call).getAKeyword().getArg()="compressed"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Subscript).
    //     getAChildNode().(Attribute).getAttr()="registrar_data"
    //     // and
    //     // name_fixed.getParentNode().(AssignStmt).getAChildNode().(Subscript).
    //     // getAChildNode().(Attribute).getAChildNode().(Name).getId()="self"
    // )
    // or
    // (
    //     // 255
    //     name_fixed.getId()="compress"
    //     and
    //     name_fixed.getParentNode().(If).getBody().getAnItem().(AssignStmt).getAChildNode().(Name).getId()="quoteraw"
    //     and
    //     name_fixed.getParentNode().(If).getBody().getAnItem().(AssignStmt).getAChildNode().(Call).
    //     getAChildNode().(Attribute).getAChildNode().(Name).getId()="zlib"
    //     and
    //     name_fixed.getParentNode().(If).getBody().getAnItem().(AssignStmt).getAChildNode().(Call).
    //     getAChildNode().(Attribute).getAttr()="compress"
    //     and
    //     name_fixed.getParentNode().(If).getBody().getAnItem().(AssignStmt).getAChildNode().(Call).
    //     getAnArg().(Name).getId()="quoteraw"
    // )
    // or
    // (
    //     // 256
    //     name_fixed.getId()="quoteblob"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).
    //     getAChildNode().(Attribute).getAChildNode().(Name).getId()="base64"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).
    //     getAChildNode().(Attribute).getAttr()="b64decode"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).
    //     getAnArg().(Subscript).getAChildNode().(Name).getId()="quote_tokens"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).
    //     getAnArg().(Subscript).getAChildNode().(IntegerLiteral).getN().toString()="0"
    // )
    // // or
    // (
    //     // 257
    //     (name_fixed.getId()="retout" or name_fixed.getId()="success" )
    //     and
    //     name_fixed.getParentNode().getParentNode().(AssignStmt).
    //     getAChildNode().(Call).getAChildNode().(Attribute).getAChildNode().(Name).getId()="self"
    //     and
    //     name_fixed.getParentNode().getParentNode().(AssignStmt).
    //     getAChildNode().(Call).getAChildNode().(Attribute).getAttr()="_tpm2_checkquote"
    //     and
    //     name_fixed.getParentNode().getParentNode().(AssignStmt).
    //     getAChildNode().(Call).getAnArg().(Name).getId()="hash_alg"
    //     and
    //     name_fixed.getParentNode().getParentNode().(AssignStmt).
    //     getAChildNode().(Call).getAnArg().(Name).getId()="nonce"
    //     and
    //     name_fixed.getParentNode().getParentNode().(AssignStmt).
    //     getAChildNode().(Call).getAnArg().(Name).getId()="quote"
    //     and
    //     name_fixed.getParentNode().getParentNode().(AssignStmt).
    //     getAChildNode().(Call).getAnArg().(Name).getId()="aikTpmFromRegistrar"
    //     and
    //     name_fixed.getParentNode().getParentNode().(AssignStmt).
    //     getAChildNode().(Call).getAnArg().(Name).getId()="compressed"
    // )
    // or
//     (
//         // 258
//         name_fixed.getId()="groups"
//         and
//         name_fixed.getParentNode().(AssignStmt).getAChildNode().
//         (Call).getAChildNode().(Attribute).getAChildNode().(Name).getId()="re"
//         and
//         name_fixed.getParentNode().(AssignStmt).getAChildNode().
//         (Call).getAChildNode().(Attribute).getAttr()="split"
//         and
//         name_fixed.getParentNode().(AssignStmt).getAChildNode().
//         (Call).getAKeyword().getArg()="pattern"
//         and
//         name_fixed.getParentNode().(AssignStmt).getAChildNode().
//         (Call).getAKeyword().getArg()="string"
//         and
//         name_fixed.getParentNode().(AssignStmt).getAChildNode().
//         (Call).getAKeyword().getArg()="maxsplit"
//         and
//         name_fixed.getParentNode().(AssignStmt).getAChildNode().
//         (Call).getAKeyword().getValue().(IntegerLiteral).getN().toString()="100"
//         and
//         name_fixed.getParentNode().(AssignStmt).getAChildNode().
//         (Call).getAKeyword().getValue().(Str).getText()="[=\\s]+"
//         and
//         name_fixed.getParentNode().(AssignStmt).getAChildNode().
//         (Call).getAKeyword().getValue().(Call).getAChildNode().(Attribute).
//         getAChildNode().(Name).getId()="line"
//         and
//         name_fixed.getParentNode().(AssignStmt).getAChildNode().
//         (Call).getAKeyword().getValue().(Call).getAChildNode().(Attribute).getAttr()="strip"
//     )
        //  or
        // (
        //     // 259
        //     name_fixed.getId()="samples_per_pixel"
        //     and
        //     name_fixed.getParentNode().(Compare).getAChildNode().(Name).getId()="MAX_SAMPLESPERPIXEL"
        //     and
        //     name_fixed.getParentNode().(Compare).getAnOp().getSymbol().toString()=">"
        //     and
        //     name_fixed.getParentNode().(Compare).getParentNode() instanceof If
        // )
        // or
        // (
        //     // 260_261
        //     name_fixed.getId()="self"
        //     and
        //     name_fixed.getParentNode().(Attribute).getAttr()="_set_file_hash"
        // )
        // or
        // (
        //     // 262
        //     name_fixed.getId()="file"
        //     and
        //     
        // or
        // (
        //     // 263
        //     name_fixed.getId()="multipart_parser"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getFunc().toString()="MultiPartParser"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAKeyword().getArg()="max_files"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAKeyword().getArg()="max_fields"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAKeyword().getValue().(Name).getId()="max_files"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAKeyword().getValue().(Name).getId()="max_fields"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAnArg().
        //     (Call).getAChildNode().(Attribute).getAChildNode().(Name).getId()="self"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAnArg().
        //     (Call).getAChildNode().(Attribute).getAttr()="stream"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAChildNode().(Attribute).getAttr()="headers"
        //     )
}



from Name name_fixed, Stmt stmt
where 
isFixed(name_fixed)
select name_fixed, name_fixed.getLocation()," The file is correctly fixed"