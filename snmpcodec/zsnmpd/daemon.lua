#!/usr/bin/env lua
-- 
-- This file is part of SmithSNMP
-- Copyright (C) 2014, Credo Semiconductor Inc.
-- 
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; either version 2 of the License, or
-- (at your option) any later version.
-- 
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
-- 
-- You should have received a copy of the GNU General Public License along
-- with this program; if not, write to the Free Software Foundation, Inc.,
-- 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
--

local snmpd = require "zsnmpd.snmp"
local utils = require "zsnmpd.utils"

-------------------------------------------------------------------------------
-- setup snmp agent, load mib modules and run it.
-------------------------------------------------------------------------------

-- load mib module with error handling
local register_mib_module = function(oid_str, mib_module_name, mib_module_path)
	-- TODO: check if oid is illegal
	local oid = utils.str2oid(oid_str)
	local mib_module_file = mib_module_path..'/'..mib_module_name..'.lua'

	-- load mib module file
	local mib_module, err = loadfile(mib_module_file)
	if mib_module == nil then
		return false, err
	end

	local status, mib_group_or_err = pcall(mib_module)
	if status == false then
		return false, mib_group_or_err
	end

	return pcall(snmpd.register_mib_group, oid, mib_group_or_err, mib_module_name)
end
snmpd.load_config = function(config)
	local communities,users,mib_module_path,mib_modules = config.communities,config.users,config.mib_module_path,config.mib_modules
	if communities ~= nil and type(communities) ~= 'table' then
		print("Can't set communities for SNMPv2c agent, please check your configuration file!")
		return
	end

	if users ~= nil and type(users) ~= 'table' then
		print("Can't set users for SNMPv3 agent, please check your configuration file!")
		return
	end

	if type(mib_module_path) ~= 'string' then
		print("Can't get mib_module_path for SNMP agent, please check your configuration file!")
		return
	end

	if type(mib_modules) ~= 'table' then
		print("Can't get mib_modules for SNMP agent, please check your configuration file!")
		return
	end

	-- Sort for module reference sequence
	local mib_mod_refs = {}

	for oid_str, mib_module_name in pairs(mib_modules) do
		local row = {}
		row['oid'] = oid_str
		row['name'] = mib_module_name
		if (row['name'] == "system") then
			table.insert(mib_mod_refs, 1, row)
		else
			table.insert(mib_mod_refs, row)
		end
	end

	if communities ~= nil then
		for _, t in ipairs(communities) do
			if t.community ~= nil then
				if t.views ~= nil then
					if next(t.views) == nil then
						snmpd.set_ro_community(t.community)
					else
						for view, attribute in pairs(t.views) do
							if attribute == 'rw' then 
								snmpd.set_rw_community(t.community, utils.str2oid(view))
							else
								snmpd.set_ro_community(t.community, utils.str2oid(view))
							end
						end
					end
				end
			end
		end
	end

	if users ~= nil then
		for _, t in ipairs(users) do
			if t.user ~= nil then
				local auth_mode = 0
				local encrypt_mode = 0
				local auth_phrase = ''
				local encrypt_phrase = ''
				-- auth_phrase
				if t.auth_mode ~= nil and t.auth_phrase ~= nil then
					if t.auth_mode == 'md5' then
						auth_mode = 0
					elseif t.auth_mode == 'sha' then
						auth_mode = 1
					end
					auth_phrase = t.auth_phrase
				end
				-- encrypt_phrase
				if t.encrypt_mode ~= nil and t.encrypt_phrase ~= nil then
					if t.encrypt_mode == 'aes' then
						encrypt_mode = 1
					end
					encrypt_phrase = t.encrypt_phrase
				end
				-- create user
				snmpd.user_create(t.user, auth_mode, auth_phrase, encrypt_mode, encrypt_phrase)
				-- mib views
				if t.views ~= nil then
					if next(t.views) == nil then
						snmpd.set_ro_user(t.user)
					else
						for view, attribute in pairs(t.views) do
							if attribute == 'rw' then 
								snmpd.set_rw_user(t.user, utils.str2oid(view))
							else
								snmpd.set_ro_user(t.user, utils.str2oid(view))
							end
						end
					end
				end
			end
		end
	end

	if snmpd.init() == false then
		return nil
	end

	for i, v in ipairs(mib_mod_refs) do
		status, err = register_mib_module(v['oid'], v['name'], mib_module_path)
		if status ~= true then
			print("Failed to load MIB module: "..v['name'])
			print(err)
		end
	end

	mib_modules = nil
	mib_mod_refs = nil
end

return snmpd
