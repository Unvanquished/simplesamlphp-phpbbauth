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
        define('PHPBB_INSTALLED', true);
        define('PHPBB_ENVIRONMENT', 'production');
        $phpbb_root_path = $this->phpbb_root_path;
        $phpEx = substr(strrchr(__FILE__, '.'), 1);
        $GLOBALS['phpbb_root_path'] = $phpbb_root_path;
        $GLOBALS['phpEx'] = $phpEx;

        require($phpbb_root_path . 'includes/startup.' . $phpEx);
        require($phpbb_root_path . 'phpbb/class_loader.' . $phpEx);

        $phpbb_class_loader = new \phpbb\class_loader('phpbb\\', "{$phpbb_root_path}phpbb/", $phpEx);
        $phpbb_class_loader->register();

        $phpbb_config_php_file = new \phpbb\config_php_file($phpbb_root_path, $phpEx);
        global $table_prefix;
        extract($phpbb_config_php_file->get_all());

        if (!defined('PHPBB_ENVIRONMENT'))
        {
            @define('PHPBB_ENVIRONMENT', 'production');
        }

        // In case $phpbb_adm_relative_path is not set (in case of an update), use the default.
        $phpbb_adm_relative_path = (isset($phpbb_adm_relative_path)) ? $phpbb_adm_relative_path : 'adm/';
        $phpbb_admin_path = (defined('PHPBB_ADMIN_PATH')) ? PHPBB_ADMIN_PATH : $phpbb_root_path . $phpbb_adm_relative_path;

        // Include files
        require($phpbb_root_path . 'includes/functions.' . $phpEx);
        require($phpbb_root_path . 'includes/functions_content.' . $phpEx);
        include($phpbb_root_path . 'includes/functions_compatibility.' . $phpEx);

        require($phpbb_root_path . 'includes/constants.' . $phpEx);
        require($phpbb_root_path . 'includes/utf/utf_tools.' . $phpEx);

        // Registered before building the container so the development environment stay capable of intercepting
        // the container builder exceptions.
        if (PHPBB_ENVIRONMENT === 'development')
        {
            \phpbb\debug\debug::enable();
        }
        else
        {
            set_error_handler(defined('PHPBB_MSG_HANDLER') ? PHPBB_MSG_HANDLER : 'msg_handler');
        }

        $phpbb_class_loader_ext = new \phpbb\class_loader('\\', "{$phpbb_root_path}ext/", $phpEx);
        $phpbb_class_loader_ext->register();

        // Set up container
        try
        {
            global $phpbb_container;
            $phpbb_container_builder = new \phpbb\di\container_builder($phpbb_root_path, $phpEx);
            $phpbb_container = $phpbb_container_builder->with_config($phpbb_config_php_file)->get_container();
        }
        catch (InvalidArgumentException $e)
        {
            if (PHPBB_ENVIRONMENT !== 'development')
            {
                trigger_error(
                    'The requested environment ' . PHPBB_ENVIRONMENT . ' is not available.',
                    E_USER_ERROR
                );
            }
            else
            {
                throw $e;
            }
        }

        if ($phpbb_container->getParameter('debug.error_handler'))
        {
            \phpbb\debug\debug::enable();
        }

        $phpbb_class_loader->set_cache($phpbb_container->get('cache.driver'));
        $phpbb_class_loader_ext->set_cache($phpbb_container->get('cache.driver'));

        $phpbb_container->get('dbal.conn')->set_debug_sql_explain($phpbb_container->getParameter('debug.sql_explain'));
        $phpbb_container->get('dbal.conn')->set_debug_load_time($phpbb_container->getParameter('debug.load_time'));
        require($phpbb_root_path . 'includes/compatibility_globals.' . $phpEx);

        register_compatibility_globals();


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
