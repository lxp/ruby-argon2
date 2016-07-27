JRUBY_HOME = ENV['JRUBY_HOME']

if JRUBY_HOME
	GEM_HOME = File.expand_path('../../..', __FILE__)
	ENV['GEM_HOME'] = GEM_HOME

	system(File.join(JRUBY_HOME, 'tool/jt.rb') + ' cextc ' + GEM_HOME)
end
