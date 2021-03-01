project('paho.mqtt.embedded-c', 'c')

srcs = [
    'MQTTPacket/src/MQTTConnectClient.c',
    'MQTTPacket/src/MQTTConnectServer.c',
    'MQTTPacket/src/MQTTDeserializePublish.c',
    'MQTTPacket/src/MQTTFormat.c',
    'MQTTPacket/src/MQTTPacket.c',
    'MQTTPacket/src/MQTTSerializePublish.c',
    'MQTTPacket/src/MQTTSubscribeClient.c',
    'MQTTPacket/src/MQTTSubscribeServer.c',
    'MQTTPacket/src/MQTTUnsubscribeClient.c',
    'MQTTPacket/src/MQTTUnsubscribeServer.c',
    'MQTTClient-C/src/linux/MQTTLinux.c',
    'MQTTClient-C/src/MQTTClient.c',
]

libpaho_embed_mqtt3c_includes = [
    include_directories('MQTTPacket/src'),
    include_directories('MQTTClient-C/src'),
    include_directories('MQTTClient-C/src/linux'),
]

libpaho_embed_mqtt3c_cflags = [
    '-DMQTTCLIENT_PLATFORM_HEADER=MQTTLinux.h',
]

cc = meson.get_compiler('c')

librt = cc.find_library('rt')

libpaho_embed_mqtt3c_dependencies = []

if get_option('default_library') == 'shared'
    libpaho_embed_mqtt3c_cflags += ['-DLINUX_SO']

    libpaho_embed_mqtt3c = shared_library('paho-embed-mqtt3c',
                                          srcs,
                                          include_directories: libpaho_embed_mqtt3c_includes,
                                          c_args: libpaho_embed_mqtt3c_cflags,
                                          dependencies: librt,
                                          gnu_symbol_visibility: 'hidden',
                                          soversion: 1)
else
    libpaho_embed_mqtt3c = static_library('paho-embed-mqtt3c',
                                          srcs,
                                          include_directories: libpaho_embed_mqtt3c_includes,
                                          c_args: libpaho_embed_mqtt3c_cflags)
    libpaho_embed_mqtt3c_dependencies += librt
endif

libpaho_embed_mqtt3c_dependency = declare_dependency(include_directories: libpaho_embed_mqtt3c_includes,
                                                     link_with: libpaho_embed_mqtt3c,
                                                     compile_args: libpaho_embed_mqtt3c_cflags,
                                                     dependencies: libpaho_embed_mqtt3c_dependencies)

if not meson.is_subproject()
    foreach name: ['pub0sub1', 'qos0pub']
        executable(name,
                   'MQTTPacket/samples/@0@.c'.format(name),
                   'MQTTPacket/samples/transport.c',
                   dependencies: libpaho_embed_mqtt3c_dependency)
    endforeach

    executable('stdoutsubc',
               'MQTTClient-C/samples/linux/stdoutsub.c',
                dependencies: libpaho_embed_mqtt3c_dependency)

    test1 = executable('test1',
                       'MQTTPacket/test/test1.c',
                       dependencies: libpaho_embed_mqtt3c_dependency)
    test('test1', test1)

    test1c = executable('test1c',
                        'MQTTClient-C/test/test1.c',
                        'MQTTClient-C/src/linux/MQTTLinux.c',
                        dependencies: libpaho_embed_mqtt3c_dependency)
    test('test1c',
         test1c,
         timeout: 600)
endif