<?php
class sspmod_phpbbauth_Auth_Source_Auth extends sspmod_core_Auth_UserPassBase {

    private $phpbb_root_path;

    public function __construct($info, $config) {
        parent::__construct($info, $config);
        if (!is_string($config['phpbb_root'])) {
            throw new Exception('Missing or invalid dsn option in config.');
        }

        $this->phpbb_root_path = $config['phpbb_root'];
    }

    protected function login($username, $password) {
        define('IN_PHPBB', true);
        $phpbb_root_path = $this->phpbb_root_path;
        $phpEx = substr(strrchr(__FILE__, '.'), 1);
        $GLOBALS['phpbb_root_path'] = $phpbb_root_path;
        $GLOBALS['phpEx'] = $phpEx;
        require_once($phpbb_root_path . 'includes/startup.' . $phpEx);
        require_once($phpbb_root_path . 'phpbb/class_loader.' . $phpEx);
        // Include files
        require_once($phpbb_root_path . 'includes/functions.' . $phpEx);
        require_once($phpbb_root_path . 'includes/functions_content.' . $phpEx);
        require_once($phpbb_root_path . 'includes/functions_compatibility.' . $phpEx);

        require_once($phpbb_root_path . 'includes/utf/utf_tools.' . $phpEx);
        $phpbb_class_loader = new \phpbb\class_loader('phpbb\\', "{$phpbb_root_path}phpbb/", $phpEx);
        $phpbb_class_loader->register();
        $phpbb_config_php_file = new \phpbb\config_php_file($phpbb_root_path, $phpEx);
        extract($phpbb_config_php_file->get_all());
        require_once($phpbb_root_path . 'includes/constants.' . $phpEx);
        $phpbb_class_loader_ext = new \phpbb\class_loader('\\', "{$phpbb_root_path}ext/", $phpEx);
        $phpbb_class_loader_ext->register();

        // Set up container
        $phpbb_container_builder = new \phpbb\di\container_builder($phpbb_config_php_file, $phpbb_root_path, $phpEx);
        $phpbb_container = $phpbb_container_builder->get_container();
        $config = $phpbb_container->get('config');
        set_config(null, null, null, $config);
        set_config_count(null, null, null, $config);
	global $user;
	global $db;
	$user = $phpbb_container->get('user');
	$db = $phpbb_container->get('dbal.conn');
	global $phpbb_extension_manager;
	$phpbb_extension_manager = $phpbb_container->get('ext.manager');
        $provider_collection = $phpbb_container->get('auth.provider_collection');
        $phpbb_container->get('request')->enable_super_globals();
        $auth = $provider_collection->get_provider('auth.provider.db');
        $ret = $auth->login($username, $password);
        if (!$ret || $ret['status'] != LOGIN_SUCCESS) {
            throw new SimpleSAML_Error_Error('WRONGUSERPASS');
        }
        $row = $ret['user_row'];

       $sql = "SELECT phpbb_groups.group_name FROM `phpbb_user_group` LEFT JOIN phpbb_groups ON
        phpbb_user_group.group_id = phpbb_groups.group_id WHERE user_id=" . (int)$row['user_id'];
        $ret = $db->sql_query($sql);
        $groups = array();
        foreach ($db->sql_fetchrowset($ret) as $entry) {
            $groups[] = $entry['group_name'];
        }
        $db->sql_freeresult($ret);
        $attributes = array(
            'uid' => array($row['user_id']),
            'name' => array($row['username']),
            'username' => array($row['username']),
            'email' => array($row['user_email']),
            'groups' => $groups,
        );
        return $attributes;
    }
}
