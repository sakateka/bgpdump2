project('bgpdump2', 'c', version: '2.0.14')

conf = configuration_data()
conf.set_quoted('PACKAGE_VERSION', meson.project_name() + '-' + meson.project_version())
configure_file(output: 'config.h', configuration: conf)
configuration_inc = include_directories('.')

deps = [
  dependency('zlib', version: '>=1.2.8'),
  dependency('bzip2'),
]

subdir('src')
