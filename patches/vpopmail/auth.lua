--Thanks to Tyler Simpkin

--End user editable values

local databasebase = "/home/vpopmail/domains"
local defaultdomain = "yourdomain.tld"
local returnuid = 520
local returngid = 520

--Supporting functions----------------


--Check if a file exists
function file_exists(name)
   local f=io.open(name,"r")
   if f~=nil then io.close(f) return true else return false end
end

--Split username and domain portions of an email address
function split(inputstr, sep) 
        sep=sep or '%s' 
        local t={}  
        for field,s in string.gmatch(inputstr, "([^"..sep.."]*)("..sep.."?)") do 
                table.insert(t,field)  
                if s=="" then 
                        return t 
                end 
        end 
end

-- Get all subdirectories of a directory (1 level)
function scandir(directory)
    local i, t, popen = 0, {}, io.popen
    local pfile = popen('ls -d '..directory..'/*/')
    for filename in pfile:lines() do
        print("Filename: "..filename)
        i = i + 1
        t[i] = filename
    end
    pfile:close()
    return t
end

--DoveCot called fuctions ------------

-- Find user / password / home in database
function db_lookup(fullusername)

   --Convert to lower case
   fullusername = string.lower(fullusername)

   local username = ""
   local domain = ""

   -- Check for existance of an @
   if string.match (fullusername, "@") then
        local splituser = split(fullusername, "@" )
        username = splituser[1]
        domain = splituser[2]
   else
        username = fullusername
        domain = defaultdomain
   end
   
   --Create real path where dB resides
   local database = databasebase .. "/" .. domain .. "/vpasswd"

   if (file_exists(database)) then

           for line in io.lines(database) do

                local userparams = split(line, ":")
                local user = userparams[1]
       
                if (user == username) then
                        return {result=0, password=userparams[8], home=userparams[6]}
                end
        end
   end
   return {result=-1}
end

function auth_passdb_lookup(req)
   res = db_lookup(req.user)
   if res.result == 0 then
       return dovecot.auth.PASSDB_RESULT_OK, "password=" .. res.password
   end
   return dovecot.auth.PASSDB_RESULT_USER_UNKNOWN, ""
end

function auth_userdb_lookup(req)
   res = db_lookup(req.user)
   if res.result == 0 then
       -- you can add additional information here for userdb, like uid or home
       return dovecot.auth.USERDB_RESULT_OK, "uid="..returnuid.." gid="..returngid.." home="..res.home
   end
   return dovecot.auth.USERDB_RESULT_USER_UNKNOWN, ""
end

function auth_userdb_iterate()
  users = {}
  
  for _,domain in ipairs(scandir(databasebase)) do


        --Create real path where dB resides
        local database = domain .. "vpasswd"

        print("Current vpasswd file: "..database)

        if (file_exists(database)) then

           --split path into array of folders after removing the trailing /
           local splitpath=split(domain:sub(1, #domain -1),"/")
           local rawdomain

           --last piece of path is domain
           for _,path in ipairs(splitpath) do
                rawdomain=path
           end

           for line in io.lines(database) do

                local userparams = split(line, ":")
                local user = userparams[1]

                table.insert(users, user.."@"..rawdomain)     
           end
        end
   end

   return users
end

--Testing for API function operation
--Dovecot relies on these

--Testing for working db_lookup()
--x =db_lookup("user@email.address")
--
--print (x.password)
--print (x.home)

--Testing for working auth_userdb_iterate
--for index,data in ipairs(auth_userdb_iterate()) do
--      print (data)
--end

