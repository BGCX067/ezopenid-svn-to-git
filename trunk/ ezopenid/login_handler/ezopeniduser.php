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


class eZOpenIDUser extends eZUser
{
	function eZOpenIDUser()
	{
	}
    
	static function loginUser( $login, $password, $authenticationMatch = false )
	{
        	$moduleINI = eZINI::instance( 'module.ini' );
        	$siteINI = eZINI::instance( 'site.ini' );
        	$rpxApiKey = $moduleINI->variable( 'ModuleSettings', 'RPXApiKey' );
        	$attributeID = $moduleINI->variable( 'ModuleSettings', 'OpenIDAttributeID' );
        	$openidUser = new eZOpenIDUser();
        	$http = eZHTTPTool::instance();

		//RPX login
		if(  $http->hasPostVariable('token') ) 
		{
			$token = $http->postVariable( 'token' );
			$post_data = array('token' => $http->postVariable( 'token' ),
				     'apiKey' => $rpxApiKey,
				     'format' => 'json');
	 
			$ezopenid = new eZOpenID();
			
			$form = $ezopenid->submitForm();
			if (!$form) return false;
			
			$post_data=$ezopenid->httpBuildQuery($post_data);					
			$response = $form->post("https://rpxnow.com/api/v2/auth_info", $post_data);
			if (!$response) return false;
			
			$raw_json = $response->body;
			if (!$raw_json) return false;
			
			$auth_info = json_decode($raw_json, true);
				 
			if ($auth_info['stat'] == 'ok') 
			{
	  
				$profile = $auth_info['profile'];
				$identifier = $profile['identifier'];

				if (isset($profile['photo'])) 
				{
					$photo_url = $profile['photo'];
				}

				if (isset($profile['displayName'])) 
				{
					$name = $profile['displayName'];
				}

				if (isset($profile['email'])) 
				{
					$email = $profile['email'];
				}
								
				if ( $identifier or $email )
				{
					
					$http->setSessionVariable( 'Token',1);
			
					if ( $siteINI->variable( 'UserSettings', 'RequireUniqueEmail' )=='true' )
					{
						$user = $openidUser->LogInOpenIDUser( false, $email);
						
						if ($user)
						{
							return $user;
						}
					}
					
					$user = $openidUser->LogInOpenIDUser( $identifier, false);
					
					if ( $user )
					{
						return $user;
					}
					else
					{
						//On demand: for functionality to register a new account automatically, contact info@contactivity.com
					}
				}
			} 
			return false;
		}
		
		//OpenID login
		elseif( $http->hasPostVariable('OpenIDURL') or $http->hasSessionVariable('OpenIDURL') )
		{ 
			if ( !$http->hasSessionVariable('OpenIDURL') )
			{
				if ( !$http->hasPostVariable( 'OpenIDURL') ) return false;
				
				$url = $http->postVariable( 'OpenIDURL');		
				$ezopenid = new eZOpenID();
				$identifier = $ezopenid->normalizeUrl( $url );
				if (!$identifier) return false;
				
				$consumer = $ezopenid->getConsumer();
				if (!$consumer) return false;
				
				$auth_request = $consumer->begin($identifier);
				if (!$auth_request) return false;
				
				$redirect_url = $auth_request->redirectURL( $ezopenid->getTrustRoot(), $ezopenid->getReturnTo('login') );
				if (!$redirect_url) return false;
				
				$http->setSessionVariable( 'OpenIDURL',$identifier);
				return eZHTTPTool::redirect( $redirect_url );
				eZExecution::cleanExit();
			}
			else
			{
				$identifier = $http->sessionVariable( 'OpenIDURL' );
				$http->removeSessionVariable( 'OpenIDURL' );
				
				$ezopenid = new eZOpenID();
				$consumer = $ezopenid->getConsumer();
				$return_to = $ezopenid->getReturnTo('login');
				$auth_info = $consumer->complete($return_to);
				
				if ( $auth_info->status == "success" and $identifier) 
				{
					$user = $openidUser->LogInOpenIDUser( $identifier, false);
					
					if ( $user )
					{
						return $user;	 
					}
					else
					{
						//On demand: for functionality to register a new account automatically, contact info@contactivity.com
					}
				}
			}
		}
		
		return false;
	}
        
        
        function LogInOpenIDUser( $identifier = false, $email = false)
        {
        	$moduleINI = eZINI::instance( 'module.ini' );
        	$attributeID = $moduleINI->variable( 'ModuleSettings', 'OpenIDAttributeID' );
        	$nodeID = $moduleINI->variable( 'ModuleSettings', 'DefaultUserPlacement' );;
        
        	if ( $email)
     		{
     			$userByEmail = eZUser::fetchByEmail( $email );
			if ( $userByEmail  and $userByEmail->isEnabled() )
			{
				$userID = $userByEmail->attribute( 'contentobject_id' );
				eZUser::setCurrentlyLoggedInUser( $userByEmail, $userID );
				eZUser::updateLastVisit( $userID );
				eZUser::setFailedLoginAttempts( $userID, 0 );
				return $userByEmail;
			}
     		}
     		else
     		{
			$params = array('AttributeFilter'=>array(array($attributeID,'=',$identifier)),
						'ClassFilterType'=>'include',
						'ClassFilterArray'=>array('user'),
						'Limit' => 1,
						'Limitation'=>array());
		
			$userSubTree = eZContentObjectTreeNode::subTreeByNodeID( $params, $nodeID );
		
			if ( count($userSubTree) == 1 )
			{
				$userContentObjectID = $userSubTree[0]->attribute('contentobject_id');
				$user = eZUser::fetch( $userContentObjectID, true );

				if ( $user and $user->isEnabled() )
				{
					$userID = $user->attribute( 'contentobject_id' );
					eZUser::setCurrentlyLoggedInUser( $user, $userID );
					eZUser::updateLastVisit( $userID );
					eZUser::setFailedLoginAttempts( $userID, 0 );
					return $user;
				}   
			}
		}
		
		return false;
        }   

}

?>