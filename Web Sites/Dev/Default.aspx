﻿<%@ Page Language="C#" AutoEventWireup="true"  %>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title></title>
    <script language="javascript" src="bclr_1.js" type="text/javascript"></script>
    <script language="javascript" src="bclr_2.js" type="text/javascript"></script>
    <script language="javascript" src="bclr_3.js" type="text/javascript"></script>
    <script language="javascript" src="bclr_mscorlib.js" type="text/javascript"></script>

    <script language="javascript" type="text/javascript">
    var appDomain = new AppDomain();
    appDomain.loadAssembly("SimpleApp", function(a) {
        a.run();
    });
        </script>
</head>
<body>
    <form id="form1" runat="server">
    <div>
    
    </div>
    </form>
</body>
</html>
