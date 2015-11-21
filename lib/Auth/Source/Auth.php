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
        $provider_collection = $phpbb_container->get('auth.provider_collection');
        $phpbb_container->get('request')->enable_super_globals();
        $auth = $provider_collection->get_provider('auth.provider.db');
        $ret = $auth->login($username, $password);
        if (!$ret || $ret['status'] != LOGIN_SUCCESS) {
            throw new SimpleSAML_Error_Error('WRONGUSERPASS');
        }
        $row = $ret['user_row'];
        $attributes = array(
            'uid' => $row['user_id'],
            'name' => $row['username'],
            'username' => $row['username'],
            'email' => $row['user_email'],
        );
        return $attributes;
    }
}
