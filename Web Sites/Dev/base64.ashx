<%@ WebHandler Language="C#" Class="base64" %>

using System;
using System.Web;

public class base64 : IHttpHandler {

    const string DataFilesRoot = @"~/App_Data/";
        
    public void ProcessRequest (HttpContext context) {
        string path = context.Request["path"];
        ValidatePath(path);
        string fullpath = context.Server.MapPath(DataFilesRoot + path);
        if (System.IO.File.Exists(fullpath))
        {
            byte[] data = System.IO.File.ReadAllBytes(fullpath);

            context.Response.ContentType = "text/plain";
            context.Response.Write(Convert.ToBase64String(data, Base64FormattingOptions.InsertLineBreaks));
        }
        else
        {
            context.Response.Status = "404 Not found";
        }
        
    }


    static char[] ForbidenChars = {'/', '\\', '%', '>', '<', ':', '&' };
    static void ValidatePath(string path)
    {
        if (String.IsNullOrEmpty(path))
            throw new ArgumentException("path cannot be empty");

        int index = path.IndexOfAny(ForbidenChars);
        if(index >= 0)
            throw new ArgumentException(String.Format("path contains invalid symbol at {0}", index));
    }
 
    public bool IsReusable {
        get {
            return false;
        }
    }

}