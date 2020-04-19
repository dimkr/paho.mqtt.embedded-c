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

libpaho_embed_mqtt33_dependencies = []

default_library = get_option('default_library')

if get_option('ssl')
    cmake = import('cmake')

    mbedtls_options = [
        '-DENABLE_PROGRAMS=OFF',
        '-DUSE_PKCS11_HELPER_LIBRARY=OFF',
        '-DINSTALL_MBEDTLS_HEADERS=OFF',
    ]

    if default_library != 'static'
        mbedtls_options += [
            '-DUSE_STATIC_MBEDTLS_LIBRARY=OFF',
            '-DUSE_SHARED_MBEDTLS_LIBRARY=ON',
        ]
    endif

    mbedtls = cmake.subproject('mbedtls', cmake_options: mbedtls_options)

    libmbedtls = mbedtls.dependency('mbedtls')
    libmbedx509 = mbedtls.dependency('mbedx509')
    libmbedcrypto = mbedtls.dependency('mbedcrypto')

    libpaho_embed_mqtt3c_cflags += ['-DMQTT_SSL']
    libpaho_embed_mqtt3c_includes += include_directories('subprojects/mbedtls/include')
    libpaho_embed_mqtt33_dependencies += [libmbedtls, libmbedx509, libmbedcrypto]

    ca_certs = custom_target('ca_certs',
                             input: 'gen_ca_certs.sh',
                             output: ['ca_certs.c', 'cert.pem', 'certdata.txt'],
                             command: [
                                 find_program('sh'),
                                 '-e',
                                 '@INPUT@',
                                 join_paths(meson.source_root(), 'curl', 'lib', 'mk-ca-bundle.pl'),
                                 '@OUTPUT0@',
                             ])
    srcs += ca_certs[0]
endif

if default_library != 'static'
    libpaho_embed_mqtt3c_cflags += ['-DLINUX_SO']

    libpaho_embed_mqtt3c = shared_library('paho-embed-mqtt3c',
                                          srcs,
                                          include_directories: libpaho_embed_mqtt3c_includes,
                                          c_args: libpaho_embed_mqtt3c_cflags,
                                          gnu_symbol_visibility: 'hidden',
                                          soversion: 1,
                                          dependencies: libpaho_embed_mqtt33_dependencies,
                                          install: true)
else
    libpaho_embed_mqtt3c = static_library('paho-embed-mqtt3c',
                                          srcs,
                                          include_directories: libpaho_embed_mqtt3c_includes,
                                          c_args: libpaho_embed_mqtt3c_cflags,
                                          dependencies: libpaho_embed_mqtt33_dependencies,
                                          install: not meson.is_subproject())
endif

libpaho_embed_mqtt3c_dependency = declare_dependency(include_directories: libpaho_embed_mqtt3c_includes,
                                                     link_with: libpaho_embed_mqtt3c,
                                                     compile_args: libpaho_embed_mqtt3c_cflags)

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
                        dependencies: libpaho_embed_mqtt3c_dependency)
    test('test1c',
         test1c,
         timeout: 600)
endif