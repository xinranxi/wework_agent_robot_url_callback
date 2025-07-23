import os
import json
import yaml
import logging

logger = logging.getLogger(__name__)

def load_config():
    """
    Load configuration from file or environment variables.
    Configuration can be provided in JSON or YAML format.
    """
    # First, check if a config file exists
    config_file_path = os.environ.get('CONFIG_FILE', 'config.yaml')
    config = {}

    if os.path.exists(config_file_path):
        try:
            if config_file_path.endswith('.json'):
                with open(config_file_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            elif config_file_path.endswith(('.yaml', '.yml')):
                with open(config_file_path, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f)
            logger.info(f"Configuration loaded from file: {config_file_path}")
        except Exception as e:
            logger.error(f"Error loading configuration file: {str(e)}")
    else:
        # If no config file, try to load from environment
        logger.info(f"Config file not found: {config_file_path}. Trying environment variables.")
        try:
            # Load corp_id from environment
            corp_id = os.environ.get('WEWORK_CORP_ID')
            if not corp_id:
                logger.warning("WEWORK_CORP_ID not found in environment")
            
            config = {'corp_id': corp_id, 'agents': []}
            
            # Load agent configurations from environment
            # Format: WEWORK_AGENT_{id}_TOKEN, WEWORK_AGENT_{id}_AES_KEY, WEWORK_AGENT_{id}_WEBHOOK
            agent_ids = set()
            
            # Find all agent IDs from environment variables
            for key in os.environ:
                if key.startswith('WEWORK_AGENT_') and '_TOKEN' in key:
                    agent_id = key.split('_TOKEN')[0].replace('WEWORK_AGENT_', '')
                    agent_ids.add(agent_id)
            
            # Load configuration for each agent ID
            for agent_id in agent_ids:
                token_key = f'WEWORK_AGENT_{agent_id}_TOKEN'
                aes_key = f'WEWORK_AGENT_{agent_id}_AES_KEY'
                webhook_key = f'WEWORK_AGENT_{agent_id}_WEBHOOK'
                secret_key = f'WEWORK_AGENT_{agent_id}_SECRET'
                
                if token_key in os.environ and aes_key in os.environ:
                    agent_config = {
                        'agent_id': agent_id,
                        'token': os.environ[token_key],
                        'encoding_aes_key': os.environ[aes_key],
                        'webhook_url': os.environ.get(webhook_key, ''),
                        'secret': os.environ.get(secret_key, '')
                    }
                    config['agents'].append(agent_config)
                    logger.info(f"Loaded configuration for agent: {agent_id}")
            
            if not config['agents']:
                logger.warning("No agent configurations found in environment variables")
                
        except Exception as e:
            logger.error(f"Error loading configuration from environment: {str(e)}")
    
    return config

def get_access_token(agent_config, corp_id):
    """
    Utility function to get access token for a specific agent.
    This can be expanded to cache tokens, handle refreshing, etc.
    """
    # This would need additional implementation to actually fetch the token
    # from WeWork APIs using the agent's secret
    pass 


def load_robot_config():
    """
    Load robot configuration from file or environment variables.
    This method is independent from load_config and specifically handles robot configurations.
    """
    config_file_path = os.environ.get('CONFIG_FILE', 'config.yaml')
    robots = []

    if os.path.exists(config_file_path):
        try:
            if config_file_path.endswith(('.yaml', '.yml')):
                with open(config_file_path, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f)
                    if 'robot' in config:
                        robots = config['robot']
                        logger.info(f"Robot configurations loaded from file: {config_file_path}")
                    else:
                        logger.warning("No 'robot' section found in config file")
        except Exception as e:
            logger.error(f"Error loading robot configuration file: {str(e)}")
    else:
        logger.info(f"Config file not found: {config_file_path}. Trying environment variables for robot configurations.")
        try:
            # Load robot configurations from environment
            # Format: WEWORK_ROBOT_{id}_TOKEN, WEWORK_ROBOT_{id}_AES_KEY, WEWORK_ROBOT_{id}_WEBHOOK
            robot_ids = set()

            for key in os.environ:
                if key.startswith('WEWORK_ROBOT_') and '_TOKEN' in key:
                    robot_id = key.split('_TOKEN')[0].replace('WEWORK_ROBOT_', '')
                    robot_ids.add(robot_id)

            for robot_id in robot_ids:
                token_key = f'WEWORK_ROBOT_{robot_id}_TOKEN'
                aes_key = f'WEWORK_ROBOT_{robot_id}_AES_KEY'
                webhook_key = f'WEWORK_ROBOT_{robot_id}_WEBHOOK'

                if token_key in os.environ and aes_key in os.environ:
                    robot_config = {
                        'robot_id': robot_id,
                        'token': os.environ[token_key],
                        'encoding_aes_key': os.environ[aes_key],
                        'webhook_url': os.environ.get(webhook_key, ''),
                    }
                    robots.append(robot_config)
                    logger.info(f"Loaded configuration for robot: {robot_id}")

            if not robots:
                logger.warning("No robot configurations found in environment variables")

        except Exception as e:
            logger.error(f"Error loading robot configuration from environment: {str(e)}")

    return robots