import re

with open('src/channel/mpsc.rs', 'r') as f:
    content = f.read()

# Replace start
pattern_start = r'let lab = LabRuntime::new\(LabConfig::new\(config\.seed\)\);\s+let result =\s*lab\.spawn_test_scope\(Budget::with_millis\(\d+\), move \|cx, scope\| async move \{'
replacement_start = r'''crate::lab::runtime::test(config.seed, |lab| {
                    let root = lab.state.create_root_region(Budget::INFINITE);
                    let (test_task, _) = lab.state.create_task(root, Budget::INFINITE, async move {
                        let cx = crate::cx::Cx::for_testing();
                        let scope = crate::cx::Scope::<crate::cx::FailFast>::new(root, Budget::INFINITE);
                        let _test_res: Result<(), proptest::test_runner::TestCaseError> = async {'''

content = re.sub(pattern_start, replacement_start, content)

# Replace end
# We look for:
# Ok(())
# });
# result.expect(...)
pattern_end = r'Ok\(\(\)\)\n\s*\}\);\n\n\s*result\.expect'
replacement_end = r'''Ok(())
                        }.await;
                    }).unwrap();
                    lab.scheduler.lock().schedule(test_task, 0);
                    lab.run_until_quiescent_with_report();
                });
                Result::<(), &str>::Ok(()).expect'''

content = re.sub(pattern_end, replacement_end, content)

with open('src/channel/mpsc.rs', 'w') as f:
    f.write(content)
