-- HAProxy Lua script for detecting credit card patterns in requests
-- This script inspects request bodies and headers for credit card numbers

core.register_action("tokenize_request", { "http-req" }, function(txn)
    -- Get request method
    local method = txn.sf:method()
    
    -- Only process POST, PUT, PATCH requests that might contain card data
    if method ~= "POST" and method ~= "PUT" and method ~= "PATCH" then
        return
    end
    
    -- Get content type
    local content_type = txn.sf:req_hdr("content-type") or ""
    
    -- Only process JSON and form data
    if not (content_type:match("application/json") or 
            content_type:match("application/x%-www%-form%-urlencoded") or
            content_type:match("multipart/form%-data")) then
        return
    end
    
    -- Get request body
    local body = txn.sf:req_body()
    
    if body and #body > 0 then
        -- Check if body contains credit card patterns
        -- This is a simple pattern - in production, use more sophisticated detection
        local card_pattern = "%d%d%d%d[%s%-]?%d%d%d%d[%s%-]?%d%d%d%d[%s%-]?%d%d%d%d"
        
        if body:match(card_pattern) then
            -- Set header to indicate this request needs tokenization
            txn.http:req_set_header("X-Requires-Tokenization", "true")
            
            -- Store the original destination
            local host = txn.sf:req_hdr("host") or ""
            local path = txn.sf:path() or "/"
            txn.http:req_set_header("X-Original-Destination", host .. path)
        end
    end
end)