<?php
/**
 * SC Alwaysdata - PrestaShop 8 Module
 *
 * @author    Scriptami
 * @copyright Scriptami
 * @license   Academic Free License version 3.0
 */

declare(strict_types=1);

if (!defined('_PS_VERSION_')) {
    exit;
}

$autoloadPath = __DIR__ . '/vendor/autoload.php';
if (file_exists($autoloadPath)) {
    require_once $autoloadPath;
} else {
    spl_autoload_register(function (string $class): void {
        if (strncmp($class, 'ScAlwaysdata\\', 13) === 0) {
            $file = __DIR__ . '/src/' . str_replace('\\', '/', substr($class, 13)) . '.php';
            if (file_exists($file)) {
                require_once $file;
            }
        }
    });
}

class sc_alwaysdata extends Module
{
    public const VERSION = '1.0.0';

    public const CONFIG_LOGS_PATH = 'SC_ALWAYSDATA_LOGS_PATH';
    public const CONFIG_HTACCESS_PATH = 'SC_ALWAYSDATA_HTACCESS_PATH';
    public const CONFIG_LINES_APACHE = 'SC_ALWAYSDATA_LINES_APACHE';
    public const CONFIG_LINES_HTTP   = 'SC_ALWAYSDATA_LINES_HTTP';
    public const CONFIG_LINES_PHP    = 'SC_ALWAYSDATA_LINES_PHP';
    public const CONFIG_LINES_SITES  = 'SC_ALWAYSDATA_LINES_SITES';

    public function __construct()
    {
        $this->name = 'sc_alwaysdata';
        $this->version = self::VERSION;
        $this->author = 'Scriptami';
        $this->tab = 'administration';
        $this->need_instance = 0;
        $this->ps_versions_compliancy = [
            'min' => '8.0.0',
            'max' => '8.99.99',
        ];

        parent::__construct();

        $this->displayName = $this->trans('Alwaysdata Log Viewer', [], 'Modules.Scalwaysdata.Admin');
        $this->description = $this->trans(
            'Analyse les logs Alwaysdata et gère le fichier .htaccess.',
            [],
            'Modules.Scalwaysdata.Admin'
        );
    }

    public function install(): bool
    {
        if (!parent::install()) {
            return false;
        }

        // Only set defaults if not already configured (preserve values across reinstalls)
        $defaults = [
            self::CONFIG_LOGS_PATH    => ($_SERVER['HOME'] ?? '') . '/admin/logs/',
            self::CONFIG_HTACCESS_PATH => _PS_ROOT_DIR_ . '/.htaccess',
            self::CONFIG_LINES_APACHE => 5000,
            self::CONFIG_LINES_HTTP   => 10000,
            self::CONFIG_LINES_PHP    => 5000,
            self::CONFIG_LINES_SITES  => 2000,
        ];

        foreach ($defaults as $key => $value) {
            if (Configuration::get($key) === false) {
                Configuration::updateValue($key, $value);
            }
        }

        return true;
    }

    public function uninstall(): bool
    {
        return parent::uninstall()
            && Configuration::deleteByName(self::CONFIG_LOGS_PATH)
            && Configuration::deleteByName(self::CONFIG_HTACCESS_PATH)
            && Configuration::deleteByName(self::CONFIG_LINES_APACHE)
            && Configuration::deleteByName(self::CONFIG_LINES_HTTP)
            && Configuration::deleteByName(self::CONFIG_LINES_PHP)
            && Configuration::deleteByName(self::CONFIG_LINES_SITES);
    }

    public function getContent(): void
    {
        Tools::redirectAdmin(
            $this->context->link->getAdminLink('AdminScAlwaysdata')
        );
    }
}
