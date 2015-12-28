<?php

// SOFTWARE NAME: Openid extension
// SOFTWARE RELEASE: 1.0-0
// COPYRIGHT NOTICE: Copyright (C) 2010 Contactivity BV
// SOFTWARE LICENSE: GNU General Public License v2.0
// NOTICE: >
//   This program is free software; you can redistribute it and/or
//   modify it under the terms of version 2.0  of the GNU General
//   Public License as published by the Free Software Foundation.
//
//   This program is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//   GNU General Public License for more details.
//
//   You should have received a copy of version 2.0 of the GNU General
//   Public License along with this program; if not, write to the Free
//   Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
//   MA 02110-1301, USA.
//

include_once( 'autoload.php');

$path_extra = dirname(dirname(__FILE__)).'/lib/php-openid-2.1.3';
$path = ini_get('include_path');
$path = $path_extra . PATH_SEPARATOR . $path;
ini_set('include_path', $path);
unset ($path);

class eZOpenID extends Auth_OpenID
{

	function __construct() 
	{	
	}
	
	function getStore() 
	{
		$varDirPath = realpath( eZSys::varDirectory() );
		$store_path = $varDirPath . eZSys::fileSeparator() . 'openid_consumer' ;
		if (!file_exists($store_path) && !mkdir($store_path)) 
		{
			//throw error
			exit(0);
		}
		$store = new Auth_OpenID_FileStore($store_path);
		return $store;
	}
	
	function getConsumer() 
	{
		$store = self::getStore();
		return new Auth_OpenID_Consumer($store);
	}
	
	function submitForm()
	{
		//Used by RPX
		$store = self::getStore();
		return new Auth_Yadis_PlainHTTPFetcher($store);
	}
	
	function getData() 
	{
		$store = self::getStore();
		return new Auth_OpenID_SRegResponse($store);
	}
		
	function normalizeUrl( $url )
	{
		return Auth_OpenID_urinorm( $url );
	}
	
	function getScheme() 
	{
		$scheme = 'http';
		if (isset($_SERVER['HTTPS']) and $_SERVER['HTTPS'] == 'on') 
		{
			$scheme .= 's';
		}
		return $scheme;
	}
	
	function getReturnTo( $function_name = 'login' ) 
	{
		$returnTo = sprintf("%s://%s:%s%s/%s",
			   self::getScheme(), $_SERVER['SERVER_NAME'],
			   $_SERVER['SERVER_PORT'],
			   dirname($_SERVER['PHP_SELF']),
			   $function_name);
		return $returnTo;
	}
	
	function getTrustRoot() 
	{
		$trustRoot = sprintf("%s://%s:%s%s/",
			   self::getScheme(), $_SERVER['SERVER_NAME'],
			   $_SERVER['SERVER_PORT'],
			   dirname($_SERVER['PHP_SELF']));
		return $trustRoot;
	}
}

?>
