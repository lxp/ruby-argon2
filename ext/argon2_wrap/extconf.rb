JRUBY_HOME = ENV['JRUBY_HOME']

if JRUBY_HOME
	project_root = File.expand_path('../../..', __FILE__)
	exec("#{JRUBY_HOME}/tool/jt.rb", 'cextc', project_root)
end
