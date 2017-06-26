load('api_config.js');
load('api_gpio.js');
load('api_mqtt.js');
load('api_sys.js');
load('api_timer.js');

let getInfo = function() {
	return JSON.stringify({total_ram: Sys.total_ram(), free_ram: Sys.free_ram()});
};
