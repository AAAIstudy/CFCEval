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
    //     // 114_139
    //     name_fixed.getId()="safe_redirect"
    //     and
    //     name_fixed.getParentNode().getParentNode() instanceof Return
    //     and
    //     name_fixed.getParentNode().(Call).getArg(0).(Name).getId()="request"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(1).(Str).getText()="next"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Call).getAChildNode().(Attribute).getAttr()="get_full_path"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Call).getAChildNode().(Attribute).getAChildNode().(Name).getId()="request"
    // )
    // or
    // (
    //     // 115_116_121_122_123
    //     name_fixed.getId()="safe_redirect"
    //     and
    //     name_fixed.getParentNode().getParentNode() instanceof Return
    //     and
    //     name_fixed.getParentNode().(Call).getArg(0).(Name).getId()="request"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(1).(Str).getText()="next"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Call).getAChildNode().(Attribute).getAttr()="get_absolute_url"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Call).getAChildNode().(Attribute).getAChildNode().(Name).getId()="comment"
    //     and
    //     name_fixed.getParentNode().(Call).getAKeyword().getArg()="method"
    //     and
    //     name_fixed.getParentNode().(Call).getAKeyword().getValue().(Str).getText()="POST"
    //     )
    // or
    // (
    //     // 117
    //     name_fixed.getId()="safe_redirect"
    //     and
    //     name_fixed.getParentNode().getParentNode() instanceof Return
    //     and
    //     name_fixed.getParentNode().(Call).getArg(0).(Name).getId()="request"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(1).(Str).getText()="next"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Call).getAChildNode().(Attribute).getAttr()="get_absolute_url"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Call).getAChildNode().(Attribute).getAChildNode().(Attribute).getAttr()="comment"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Call).getAChildNode().(Attribute).getAChildNode().(Attribute).getAChildNode().(Name).getId()="like"
    //     and
    //     name_fixed.getParentNode().(Call).getAKeyword().getArg()="method"
    //     and
    //     name_fixed.getParentNode().(Call).getAKeyword().getValue().(Str).getText()="POST"
    // )
    // or
    // (
    //     // 118
    //     name_fixed.getId()="safe_redirect"
    //     and
    //     name_fixed.getParentNode().getParentNode() instanceof Return
    //     and
    //     name_fixed.getParentNode().(Call).getArg(0).(Name).getId()="request"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(1).(Str).getText()="next"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Call).getAChildNode().(Attribute).getAChildNode().(Name).getId()="poll"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Call).getAChildNode().(Attribute).getAttr()="get_absolute_url"
    // )
    // or
    //  (
    //     // 119_120
    //     name_fixed.getId()="safe_redirect"
    //     and
    //     name_fixed.getParentNode().getParentNode() instanceof Return
    //     and
    //     name_fixed.getParentNode().(Call).getArg(0).(Name).getId()="request"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(1).(Str).getText()="next"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Call).getAChildNode().(Attribute).getAChildNode().(Name).getId()="poll"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Call).getAChildNode().(Attribute).getAttr()="get_absolute_url"
    //     and
    //     name_fixed.getParentNode().(Call).getAKeyword().getArg()="method"
    //     and
    //     name_fixed.getParentNode().(Call).getAKeyword().getValue().(Str).getText()="POST"
    // )
    // or
    // (
    //     // 121_122_123
    //     name_fixed.getId()="safe_redirect"
    //     and
    //     name_fixed.getParentNode().getParentNode() instanceof Return
    //     and
    //     name_fixed.getParentNode().(Call).getArg(0).(Name).getId()="request"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(1).(Str).getText()="next"
    //     and
    //     (  
    //     name_fixed.getParentNode().(Call).getArg(2).(Call).getAChildNode().(Attribute).getAttr()="get_absolute_url"
    //     or
    //     name_fixed.getParentNode().(Call).getArg(2).(Call).getAChildNode().(Name).getId()="default_url"
    //     )
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Call).getAChildNode().(Attribute).getAChildNode().(Name).getId()="comment"
    //     and
    //     name_fixed.getParentNode().(Call).getAKeyword().getArg()="method"
    //     and
    //     name_fixed.getParentNode().(Call).getAKeyword().getValue().(Str).getText()="POST"
    // )
    // or
    // (
    //     // 123_124()15 116 121 122 123
    //     name_fixed.getId()="safe_redirect"
    //     and
    //     name_fixed.getParentNode().getParentNode() instanceof Return
    //     and
    //     name_fixed.getParentNode().(Call).getArg(0).(Name).getId()="request"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(1).(Str).getText()="next"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Call).getAChildNode().(Attribute).getAChildNode().(Name).getId()="comment"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Call).getAChildNode().(Attribute).getAttr()="get_absolute_url"
    // )
    // or
    // (
    //     // 126
    //     name_fixed.getId()="safe_redirect"
    //     and
    //     name_fixed.getParentNode().getParentNode() instanceof Return
    //     and
    //     name_fixed.getParentNode().(Call).getArg(0).(Name).getId()="request"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(1).(Str).getText()="next"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Call).getAChildNode().(Attribute).getAChildNode().(Attribute).getAChildNode().(Attribute).getAChildNode().(Name).getId()="request"
    // )
    // or
//     (
//             // 127_129_130_136_138
//         name_fixed.getId()="safe_redirect"
//         and
//         name_fixed.getParentNode().getParentNode() instanceof Return
//         and
//         name_fixed.getParentNode().(Call).getArg(0).(Name).getId()="request"
//         and
//         name_fixed.getParentNode().(Call).getArg(1).(Str).getText()="next"
//         and
//         name_fixed.getParentNode().(Call).getArg(2).(Call).getAChildNode().(Attribute).getAChildNode().(Name).getId()="topic"
//         and
//         name_fixed.getParentNode().(Call).getArg(2).(Call).getAChildNode().(Attribute).getAttr()="get_absolute_url"
//         and
//         name_fixed.getParentNode().(Call).getAKeyword().getArg()="method"
//         and
//         name_fixed.getParentNode().(Call).getAKeyword().getValue().(Str).getText()="POST"
//     )
    // or
    // (
    //     // 128
    //     name_fixed.getId()="safe_redirect"
    //     and
    //     name_fixed.getParentNode().getParentNode() instanceof Return
    //     and
    //     name_fixed.getParentNode().(Call).getArg(0).(Name).getId()="request"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(1).(Str).getText()="next"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Call).getAChildNode().(Attribute).getAChildNode().(Attribute).getAChildNode().(Name).getId()="favorite"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Call).getAChildNode().(Attribute).getAChildNode().(Attribute).getAttr()="topic"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Call).getAChildNode().(Attribute).getAttr()="get_absolute_url"
    //     and
    //     name_fixed.getParentNode().(Call).getAKeyword().getArg()="method"
    //     and
    //     name_fixed.getParentNode().(Call).getAKeyword().getValue().(Str).getText()="POST"
    // )
    // or
    // (
    //     // 131
    //     name_fixed.getId()="safe_redirect"
    //     and
    //     name_fixed.getParentNode().getParentNode() instanceof Return
    //     and
    //     name_fixed.getParentNode().(Call).getArg(0).(Name).getId()="request"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(1).(Str).getText()="next"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Call).getAChildNode().(Attribute).getAChildNode().(Attribute).getAChildNode().(Name).getId()="notification"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Call).getAChildNode().(Attribute).getAChildNode().(Attribute).getAttr()="topic"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Call).getAChildNode().(Attribute).getAttr()="get_absolute_url"
    //     and
    //     name_fixed.getParentNode().(Call).getAKeyword().getArg()="method"
    //     and
    //     name_fixed.getParentNode().(Call).getAKeyword().getValue().(Str).getText()="POST"
    // )
    // or
    // (
    //     // 132
    //     name_fixed.getId()="safe_redirect"
    //     and
    //     name_fixed.getParentNode().getParentNode() instanceof Return
    //     and
    //     name_fixed.getParentNode().(Call).getArg(0).(Name).getId()="request"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(1).(Str).getText()="next"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Call).getAChildNode().(Name).getId()="reverse"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Call).getArg(0).(Str).getText()="spirit:topic:notification:index"
    //      and
    //     name_fixed.getParentNode().(Call).getAKeyword().getArg()="method"
    //     and
    //     name_fixed.getParentNode().(Call).getAKeyword().getValue().(Str).getText()="POST"
    // )
    // or
    // (
    //     // 133_136
    //     name_fixed.getId()="safe_redirect"
    //     and
    //     name_fixed.getParentNode().getParentNode() instanceof Return
    //     and
    //     name_fixed.getParentNode().(Call).getArg(0).(Name).getId()="request"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(1).(Str).getText()="next"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Lambda).getAChildNode().(Function).getBody().getAnItem().(Return).getAChildNode().(Call).getAChildNode().(Attribute).getAttr()="get_absolute_url"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Lambda).getAChildNode().(Function).getBody().getAnItem().(Return).getAChildNode().(Call).getAChildNode().(Attribute).getAChildNode().(Attribute).getAttr()="category"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Lambda).getAChildNode().(Function).getBody().getAnItem().(Return).getAChildNode().(Call).getAChildNode().(Attribute).getAChildNode().(Attribute).getAChildNode().(Name).getId()="tform"
    //     and
    //      name_fixed.getParentNode().(Call).getAKeyword().getArg()="method"
    //     and
    //     name_fixed.getParentNode().(Call).getAKeyword().getValue().(Str).getText()="POST"
    // )
    // or
    // (
    //     // 134_135_136
    //     name_fixed.getId()="safe_redirect"
    //     and
    //     name_fixed.getParentNode().getParentNode() instanceof Return
    //     and
    //     name_fixed.getParentNode().(Call).getArg(0).(Name).getId()="request"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(1).(Str).getText()="next"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Call).getAChildNode().(Attribute).getAChildNode().(Name).getId()="topic_private"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Call).getAChildNode().(Attribute).getAttr()="get_absolute_url"
    //     and
    //     name_fixed.getParentNode().(Call).getAKeyword().getArg()="method"
    //     and
    //     name_fixed.getParentNode().(Call).getAKeyword().getValue().(Str).getText()="POST"
    // )
    // or
    // (
    //     // 137
    //     name_fixed.getId()="safe_redirect"
    //     and
    //     name_fixed.getParentNode().getParentNode() instanceof Return
    //     and
    //     name_fixed.getParentNode().(Call).getArg(0).(Name).getId()="request"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(1).(Str).getText()="next"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Name).getId()="default_url"
    //     and
    //     name_fixed.getParentNode().(Call).getAKeyword().getArg()="method"
    //     and
    //     name_fixed.getParentNode().(Call).getAKeyword().getValue().(Str).getText()="POST"
    //     and
    //     name_fixed.getParentNode().getParentNode().getParentNode().(If).getBody().getAnItem().(AssignStmt).getAChildNode().getAChildNode().(Function).getAChildNode().(Return).getAChildNode().(Call).getAChildNode().(Attribute).getAChildNode().(Call).getAChildNode().(Attribute).getAChildNode().(Name).getId()="form"
    //     and
    //     name_fixed.getParentNode().getParentNode().getParentNode().(If).getBody().getAnItem().(AssignStmt).getAChildNode().getAChildNode().(Function).getAChildNode().(Return).getAChildNode().(Call).getAChildNode().(Attribute).getAChildNode().(Call).getAChildNode().(Attribute).getAttr()="get_category"
    //     and
    //     name_fixed.getParentNode().getParentNode().getParentNode().(If).getBody().getAnItem().(AssignStmt).getAChildNode().getAChildNode().(Function).getAChildNode().(Return).getAChildNode().(Call).getAChildNode().(Attribute).getAttr()="get_absolute_url"
    //     )
    //     // or
    //     (
    //          // 138_127_129_130_136_138
    //     )
    // or
    // (
    //      // 139_14_139
    // )
    // or
    // (
    //     // 140
    //     name_fixed.getId()="safe_redirect"
    //     and
    //     name_fixed.getParentNode().getParentNode() instanceof Return
    //     and
    //     name_fixed.getParentNode().(Call).getArg(0).(Name).getId()="request"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(1).(Str).getText()="next"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Call).getAChildNode().(Name).getId()="reverse"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Call).getArg(0).(Attribute).getAttr()="LOGIN_URL"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Call).getArg(0).(Attribute).getAChildNode().(Name).getId()="settings"
    // )
    // or
    // (
    //     // 141_143
    //     name_fixed.getId()="safe_redirect"
    //     and
    //     name_fixed.getParentNode().getParentNode() instanceof Return
    //     and
    //     name_fixed.getParentNode().(Call).getArg(0).(Name).getId()="request"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(1).(Str).getText()="next"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Call).getAChildNode().(Name).getId()="reverse"
    //     and
    //     name_fixed.getParentNode().(Call).getArg(2).(Call).getArg(0).(Str).getText()="spirit:user:update"
    // )
    // or
    // (
    //     // 144
    //     name_fixed.getId()="next_url"
    //     and
    //     name_fixed.getParentNode().getAChildNode().(Call).getAChildNode().(Attribute).getAChildNode().(Attribute).getAChildNode().(Name).getId()="request"
    //     and
    //     name_fixed.getParentNode().getAChildNode().(Call).getAChildNode().(Attribute).getAChildNode().(Attribute).getAttr()="args"
    //     and
    //     name_fixed.getParentNode().getAChildNode().(Call).getAChildNode().(Attribute).getAttr()="get"
    // )
    // or
    // (
    //     // 146_147_148
    // )
    // (
    //     // 149_p1
    //     name_fixed.getId()="current_team"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Attribute).getAChildNode().(Call).getAChildNode().(Name).getId()="User"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Attribute).getAChildNode().(Call).getArg(0).(Name).getId()="User"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Attribute).getAChildNode().(Call).getArg(1).(Attribute).getAChildNode().(Name).getId()="request"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Attribute).getAChildNode().(Call).getArg(1).(Attribute).getAttr()="user"
    //     and
    //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Attribute).getAttr()="team"
    //     )
    // or
    // (
    //     // 149_p1_p2
    //     name_fixed.getId()="current_team"
    //     and
    //     (
    //         name_fixed.getParentNode().(AssignStmt).getAChildNode().(Attribute).getAChildNode().(Call).getAChildNode().(Name).getId()="User"
    //         and
    //         name_fixed.getParentNode().(AssignStmt).getAChildNode().(Attribute).getAChildNode().(Call).getArg(0).(Name).getId()="User"
    //         and
    //         name_fixed.getParentNode().(AssignStmt).getAChildNode().(Attribute).getAChildNode().(Call).getArg(1).(Attribute).getAChildNode().(Name).getId()="request"
    //         and
    //         name_fixed.getParentNode().(AssignStmt).getAChildNode().(Attribute).getAChildNode().(Call).getArg(1).(Attribute).getAttr()="user"
    //         and
    //         name_fixed.getParentNode().(AssignStmt).getAChildNode().(Attribute).getAttr()="team"
    //     )
    //     or
    //     (
    //         name_fixed.getParentNode().getParentNode().(UnaryExpr).getAChildNode().(Call).getAChildNode().(Name).getId()="hostname_in_app_urls"
    //         and
    //         name_fixed.getParentNode().getParentNode().(UnaryExpr).getAChildNode().(Call).getArg(0).(Name).getId()="current_team"
    //         and
    //         name_fixed.getParentNode().getParentNode().(UnaryExpr).getAChildNode().(Call).getArg(1).(Attribute).getAttr()="hostname"
    //         and
    //         name_fixed.getParentNode().getParentNode().(UnaryExpr).getAChildNode().(Call).getArg(1).(Attribute).getAChildNode().(Name).getId()="redirect_url"
    //     )
    //     )
        // or
        // (
        //     // 151
        //     name_fixed.getId()="prevent_open_redirect"
        //     and
        //     name_fixed.getParentNode().(Call).getArg(0).(Attribute).getAChildNode().(Attribute).getAChildNode().(Name).getId()="request"
        //     and
        //     name_fixed.getParentNode().(Call).getArg(0).(Attribute).getAChildNode().(Attribute).getAttr()="vars"
        //     and
        //     name_fixed.getParentNode().(Call).getArg(0).(Attribute).getAttr()="send"
        //     and
        //     name_fixed.getParentNode().getParentNode().(AssignStmt).getAChildNode().(Name).getId()="send"
        // )
        // or
        // (
        //         // 152
        //         name_fixed.getId()="prevent_open_redirect"
        //         and
        //         name_fixed.getParentNode().(Call).getAChildNode().(Name).getId()="next"
        //         and
        //         name_fixed.getParentNode().getParentNode() instanceof Return
        // )
        // or
//         (
//             // 153_154
//             name_fixed.getId()="prevent_open_redirect"
//             and
//             name_fixed.getParentNode().(Call).getArg(0).(Attribute).getAChildNode().(Attribute).getAChildNode().(Name).getId()="request"
//             and
//             (
//                 name_fixed.getParentNode().(Call).getArg(0).(Attribute).getAChildNode().(Attribute).getAttr()="get_vars"
//                 or
//                 name_fixed.getParentNode().(Call).getArg(0).(Attribute).getAChildNode().(Attribute).getAttr()="post_vars"
//             )
//             and
//             name_fixed.getParentNode().(Call).getArg(0).(Attribute).getAttr()="_next"
//         )
        // or
        // (
        //     // 156_157_158
        //     name_fixed.getId()="validators"
        //     and
        //     (
        //         name_fixed.getParentNode().(Attribute).getAttr()="length"
        //         or
        //         name_fixed.getParentNode().(Attribute).getAttr()="regexp"
        //     )
        //    and
        //    (
        //     name_fixed.getParentNode().getParentNode().(Call).getAKeyword().getArg().toString()="min"
        //     or
        //     name_fixed.getParentNode().getParentNode().(Call).getAKeyword().getArg().toString()="max"
        //     or
        //     name_fixed.getParentNode().getParentNode().(Call).getAKeyword().getArg().toString()="message"
        //    )
        //    and
        //    (
        //     name_fixed.getParentNode().getParentNode().(Call).getAKeyword().getValue().(IntegerLiteral).getN().toString()="3"
        //     or
        //     name_fixed.getParentNode().getParentNode().(Call).getAKeyword().getAChildNode().(Call).getAChildNode().toString()="_"
        //    )       
        //     and
        //     ( 
        //         name_fixed.getParentNode().getParentNode().(Call).getAKeyword().getAChildNode().(Call).getAnArg().(Str).getText()="Username too short."
        //         or
        //         name_fixed.getParentNode().getParentNode().(Call).getAKeyword().getAChildNode().(Call).getAnArg().(Str).getText()="Must be a valid email address."
        //         or
        //         name_fixed.getParentNode().getParentNode().(Call).getAKeyword().getAChildNode().(Call).getAnArg().(Str).getText()="Must not contain any special characters."   
        //     )
           
        //         // and
        // //    (
        // //     name_fixed.getParentNode().getParentNode().(Call).getArg(0).(Attribute).getAttr()="PATTERN_USERNAME"
        // //     or
        // //     name_fixed.getParentNode().getParentNode().(Call).getArg(0).(Attribute).getAttr()="PATTERN_FULLNAME"
        // //     or
        // //     name_fixed.getParentNode().getParentNode().(Call).getArg(0).(Attribute).getAttr()="PATTERN_EMAIL"
        // //    )
        // )
        // or
        // (
        //     // 159_160
        //     (
        //         name_fixed.getId()="Regexp"
        //         or
        //         name_fixed.getId()="Length"
        //     )
        //     and
        //     (
        //         name_fixed.getParentNode().(Call).getAnArg().(Attribute).getAttr()="PATTERN_FULLNAME"
        //         or
        //         name_fixed.getParentNode().(Call).getAnArg().(Attribute).getAttr()="PATTERN_EMAIL"
        //     )
        //     and
        //     (
        //         name_fixed.getParentNode().(Call).getAKeyword().getAChildNode().(Call).getAChildNode().(Name).getId()="_"
        //         or
        //         name_fixed.getParentNode().(Call).getAKeyword().getAChildNode().(IntegerLiteral).getN().toString()="256"
        //     )
            
        //    and
        //    (
        //     name_fixed.getParentNode().(Call).getAKeyword().getAChildNode().(Call).getAnArg().(Str).getText()="Must not contain any special characters."
        //    or
        //    name_fixed.getParentNode().(Call).getAKeyword().getAChildNode().(Call).getAnArg().(Str).getText()="Email too long."
        //    or
        //    name_fixed.getParentNode().(Call).getAKeyword().getAChildNode().(Call).getAnArg().(Str).getText()="Must be a valid email address."
        //     )
         
        // )
        // or
        // (
        //     // 162_164
        //     name_fixed.getId()="return_to"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getValue().(Call).getAChildNode().(Attribute).getAttr()="get"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getValue().(Call).getAChildNode().(Attribute).getAChildNode().(Attribute).getAttr()="GET"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getValue().(Call).getAChildNode().(Attribute).getAChildNode().(Attribute).getAChildNode().(Attribute).getAttr()="request"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getValue().(Call).getAChildNode().(Attribute).getAChildNode().(Attribute).getAChildNode().(Attribute).getAChildNode().(Name).getId()="self"
        //     and
        //     (
        //         name_fixed.getParentNode().(AssignStmt).getValue().(Call).getArg(0).(Str).getText()="returnTo"
        //         or
        //         name_fixed.getParentNode().(AssignStmt).getValue().(Call).getArg(0).(Str).getText()="/"
        //     )
        // )
        // or
        // (
        //     // 163
        //     name_fixed.getId()="return_url"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAChildNode().(Attribute).getAttr()="get_return_to"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAChildNode().(Attribute).getAChildNode().(Name).getId()="self"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAnArg().(Attribute).getAttr()="POST"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAnArg().(Attribute).getAChildNode().(Attribute).getAttr()="request"
        //     and
        //     name_fixed.getParentNode().(AssignStmt).getAChildNode().(Call).getAnArg().(Attribute).getAChildNode().(Attribute).getAChildNode().(Name).getId()="self"
        // )
        // or
        // (
        //     // 165
        //     name_fixed.getId()="self"
        //     and
        //     name_fixed.getParentNode().(Attribute).getAttr()="success_url"
        //     and
        //     name_fixed.getParentNode().getParentNode().(AssignStmt).getAChildNode().(Call).getAChildNode().(Attribute).getAttr()="get_return_to"
        //     and
        //     name_fixed.getParentNode().getParentNode().(AssignStmt).getAChildNode().(Call).getAChildNode().(Attribute).getAChildNode().(Name).getId()="self"
        //     and
        //     name_fixed.getParentNode().getParentNode().(AssignStmt).getAChildNode().(Call).getAnArg().(Attribute).getAttr()="cleaned_data"
        //     and
        //     name_fixed.getParentNode().getParentNode().(AssignStmt).getAChildNode().(Call).getAnArg().(Attribute).getAChildNode().(Name).getId()="form"
        //     )
        // or
        (
            // 166
            name_fixed.getId()="cherrypy"
            and
            name_fixed.getParentNode().(Attribute).getAttr()="tools"
            and
            name_fixed.getParentNode().getParentNode().(Attribute).getAttr()="proxy"
            and
            (
                name_fixed.getParentNode().getParentNode().getParentNode().(Call).getAKeyword().getArg().toString()="local"
                or
                name_fixed.getParentNode().getParentNode().getParentNode().(Call).getAKeyword().getArg().toString()="remote"
            )
            and
            (
                name_fixed.getParentNode().getParentNode().getParentNode().(Call).getAKeyword().getValue().toString()="None"
                or
                name_fixed.getParentNode().getParentNode().getParentNode().(Call).getAKeyword().getValue().toString()="X-Real-IP"
            )
           
        )


}



from Name name_fixed, Stmt stmt
where 
isFixed(name_fixed)
select name_fixed, name_fixed.getLocation()," The file is correctly fixed"