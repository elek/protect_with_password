<?php
/*
Plugin Name: Protect with Password
Plugin URI: http://fixme
Description: Protect wordpress blog with one global password with RSS support
Version: 1.0
Author: Elek, Marton
Author URI: http://anzix.net
License: GPL3
*/

$SESSION_KEY="pwp_authorized";
add_action('get_header', 'pwp_checkauth');
add_filter('post_link','pwp_post_filter',1,3);
add_filter('feed_link','pwp_feed_link',1,2);

session_start();


function pwp_normalize_password($pwd){

    $pwd = strtolower($pwd);
    
    $pwd =  mb_ereg_replace('á','a',$pwd);
    $pwd =  mb_ereg_replace('ő','o',$pwd);

}

function pwp_checkauth($arg){
   if ($_REQUEST['pwplogout']){
      unset($_SESSION[$SESSION_KEY]);
      //authorized      
   } elseif ($_REQUEST['protect-with-password']){
      if (pwp_normalize_password($_REQUEST['protect-with-password'])===pwp_normalize_password(get_option('pwp_password'))){
         $_SESSION[$SESSION_KEY] = true;
      }         
   } elseif ($_REQUEST['protect-with-hash'] && sha1(pwp_normalize_password(get_option('pwp_password')))==$_REQUEST['protect-with-hash']){
      $_SESSION[$SESSION_KEY] = true;
   }

   //$_SESSION[$SESSION_KEY] = true;
   if ($_SESSION[$SESSION_KEY]!=true){
      require(WP_PLUGIN_DIR.'/protect_with_password/login.php');
      exit();
   }
   
}

function pwp_authorized_link($link){
   $pwd = sha1(pwp_normalize_password(get_option('pwp_password')));
   if (strpos($link,"?")){
      return $link."&protect-with-hash=".$pwd;
   } else {
      return $link."?protect-with-hash=".$pwd;
   }
}

function pwp_feed_link($link,$type){
    return pwp_authorized_link($link);
}

function pwp_post_filter($a1,$a2,$a3){
   return pwp_authorized_link($a1);
}
add_action('admin_menu', 'pwp_plugin_menu');

function pwp_plugin_menu() {

  add_options_page('Protect with Password', 'Password Protection', 'manage_options', 'pwpw_admin_menu', 'pwp_plugin_options');
  add_action( 'admin_init', 'pwp_register_mysettings' );
}


function pwp_register_mysettings(){
   register_setting( 'pwp-settings-group', 'pwp_password' );
   register_setting( 'pwp-settings-group', 'pwp_message' );
}

function pwp_plugin_options(){
 if (!current_user_can('manage_options'))  {
    wp_die( __('You do not have sufficient permissions to access this page.') );
  }
?>

<div class="wrap">
<h2>Protect with password</h2>

<form method="post" action="options.php">
<?php wp_nonce_field('update-options'); ?>

<table class="form-table">
<tr valign="top">
<th scope="row">Login message</th>
<td><input type="text" name="pwp_message" value="<?php echo get_option('pwp_message'); ?>" /></td>
</tr>
<tr valign="top">
<th scope="row">Password for protection</th>
<td><input type="text" name="pwp_password" value="<?php echo get_option('pwp_password'); ?>" /></td>
</tr>
</table>

<?php settings_fields( 'pwp-settings-group' ); ?>


<p class="submit">
<input type="submit" class="button-primary" value="<?php _e('Save Changes') ?>" />
</p>

</form>
</div>
<?php
}
?>
