#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <fmt/color.h>
#include <fmt/core.h>
#include <fstream>
#include <glob.h>
#include <map>
#include <string>
#include <sys/errno.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>
#include <yaml-cpp/yaml.h>

#define fs std::filesystem

std::string exec(std::string cmd) {
    std::array<char, 128> buffer;
    std::string result;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }
    int stat = pclose(pipe);
    if (WEXITSTATUS(stat)) exit(EXIT_FAILURE);
    
    return result;
}

std::string ltrim(const std::string& s) {
    size_t start = s.find_first_not_of(" \n\r\t\f\v");
    return (start == std::string::npos) ? "" : s.substr(start);
}
std::string rtrim(const std::string& s) {
    size_t end = s.find_last_not_of(" \n\r\t\f\v");
    return (end == std::string::npos) ? "" : s.substr(0, end + 1);
}
std::string trim(const std::string& s) {
    return rtrim(ltrim(s));
}
bool replace(std::string& str, const std::string& from, const std::string& to) {
    size_t start_pos = str.find(from);
    if(start_pos == std::string::npos)
        return false;
    str.replace(start_pos, from.length(), to);
    return true;
}


void nn_rule(std::ostream& buildfile, std::string out, std::string rule, std::vector<std::string> deps) {
    std::string line = fmt::format("build {}: {}", out, rule);
    for (auto dep : deps) {
        line += " " + dep;
        if (line.length() > 80) {
            buildfile << line << " $\n";
            line = "      ";
        }
    }
    if (line.length() != 6) {
        buildfile << line << "\n";
    }
}

std::vector<std::string> glob(const std::string& pattern) {
    using namespace std;

    // glob struct resides on the stack
    glob_t glob_result;
    memset(&glob_result, 0, sizeof(glob_result));

    // do the glob operation
    int return_value = glob(pattern.c_str(), GLOB_TILDE, NULL, &glob_result);
    if(return_value != 0) {
        globfree(&glob_result);
        stringstream ss;
        if (return_value == -ENOENT) {
            fmt::print(fg(fmt::color::red), "Error: no such file or directory: {}\n", pattern);
            exit(EXIT_FAILURE);
        }
        ss << "glob(" << pattern << ") failed with return_value " << return_value << endl;
        throw std::runtime_error(ss.str());
    }

    // collect all the filenames into a std::list<std::string>
    vector<string> filenames;
    for(size_t i = 0; i < glob_result.gl_pathc; ++i) {
        filenames.push_back(string(glob_result.gl_pathv[i]));
    }

    // cleanup
    globfree(&glob_result);

    // done
    return filenames;
}

struct MapRule {
    std::string in;
    std::string out;
    std::string cmd;
    bool has_depfiles;
};

std::map<std::string, MapRule> maprules;
std::map<std::string, std::vector<std::string>> virtrules;
std::map<std::string, std::string> reducerules;

std::vector<std::string> convert(std::ostream& buildfile, std::string rule, YAML::Node conf) {
    if (rule == "noop" || maprules.contains(rule)) {
        MapRule& cmd = maprules[rule];
        std::vector<std::string> deps, out;

        if (conf.IsScalar()) {
            if (conf.Scalar().starts_with('$')) {
                deps = virtrules[conf.Scalar().substr(1)];
            } else {
                deps = glob(conf.Scalar());
            }
        } else {
            if (!conf["_"].IsNull()) {
                fmt::print(fg(fmt::color::red), "Error: you cannot specify an output for maprules\n");
                exit(EXIT_FAILURE);
            }
            for (auto p : conf) {
                std::string rule = p.first.Scalar();
                YAML::Node subconf = p.second;

                for (auto dep : convert(buildfile, rule, subconf)) deps.push_back(dep);
            }
        }
        if (rule == "noop") return deps;

        for (auto dep : deps) {
            if (!dep.ends_with(cmd.in)) {
                fmt::print(fg(fmt::color::red), "Error: file '{}' cannot be applied to rule {}, with ext {}\n", dep, rule, cmd.in);
                exit(EXIT_FAILURE);
            }
            std::string mapped = dep.substr(0, dep.size() - cmd.in.size()) + cmd.out;
            if (mapped.starts_with("build/")) mapped = mapped.substr(6);
            replace(mapped, "/", ".");
            mapped = "build/" + mapped;
            nn_rule(buildfile, mapped, rule, std::vector{dep});
            if (cmd.has_depfiles) {
                buildfile << fmt::format("    depfile = {}.d\n", mapped);
            }
            out.push_back(mapped);
        }

        return out;
    } else if (reducerules.contains(rule)) {
        std::string out = conf["_"].Scalar();
        
        std::vector<std::string> deps;
        for (auto p : conf) {
            std::string rule = p.first.Scalar();
            YAML::Node subconf = p.second;

            if (rule == "_") continue;

            for (auto dep : convert(buildfile, rule, subconf)) deps.push_back(dep);
        }
        nn_rule(buildfile, out, rule, deps);
        return std::vector<std::string>{out};
    } else {
        fmt::print(fg(fmt::color::red), "Error: cannot instantiate rule {}: rule does not exist\n", rule);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char** argv) {
    if (argc != 1) {
        printf("Usage: %s\n", argv[0]);
        return EXIT_FAILURE;
    }

    fs::path preninja = fs::path("build.preninja");

    if (!fs::exists(preninja)) {
        fmt::print(fg(fmt::color::red), "Error: build.preninja does not exist\n");
        return EXIT_FAILURE;
    }

    std::ifstream in;
    in.open(preninja);
    YAML::Node root = YAML::Load(in);
    in.close();

    std::ofstream out;
    out.open("build.ninja", std::ofstream::out | std::ofstream::trunc);

    std::map<std::string, std::string> env_vars;

    for (auto envkey : root["env"]) {
        std::string name = envkey.first.Scalar();
        std::string value = envkey.second.Scalar();

        env_vars[name] = value;
    }

    for (auto pconfkey : root["pkg-config"]) {
        std::string name = pconfkey.first.Scalar();
        std::string value = pconfkey.second.Scalar();
        if (name.ends_with("cflags")) {
            env_vars[name] += " " + trim(exec(fmt::format("pkg-config --cflags {}", value)));
        } else if (name.ends_with("ldflags")) {
            env_vars[name] += " " + trim(exec(fmt::format("pkg-config --libs {}", value)));
        } else {
            fmt::print(fg(fmt::color::yellow), "Warning: unknown pkg-config type {}\n", name);
            env_vars[name] += " " + trim(exec(fmt::format("pkg-config --cflags --libs {}", value)));
        }
    }

    out << "# variables\n";
    for (auto envkey : env_vars) {
        std::string name = envkey.first;
        std::string value = envkey.second;

        out << fmt::format("{} = {}\n", name, value);
    }

    out << "# map rules\n";
    for (auto maprule : root["rules"]["map"]) {
        std::string name = maprule.first.Scalar();
        YAML::Node conf = maprule.second;

        MapRule rule {
            .in = conf["in"].Scalar(),
            .out = conf["out"].Scalar(),
            .cmd = conf["cmd"].Scalar(),
            .has_depfiles = false
        };
        rule.has_depfiles = rule.cmd.find("$depfile") != std::string::npos;

        maprules[name] = rule;
        
        out << fmt::format("rule {}\n", name);
        out << fmt::format("    command = {}\n", rule.cmd);
        out << fmt::format("    description = {} $out\n", name);
        if (rule.cmd.find("$depfile") != std::string::npos) {
            if (!conf["deps"].IsNull() && conf["deps"].Scalar() != "") {
                out << fmt::format("    deps = {}\n", conf["deps"].Scalar());
            } else {
                out << fmt::format("    deps = gcc\n");
            }
            out << fmt::format("    depfile = $depfile\n");
        }

    }

    out << "# reduce rules\n";
    for (auto reducer : root["rules"]["reduce"]) {
        std::string name = reducer.first.Scalar();
        std::string cmd = reducer.second.Scalar();

        reducerules[name] = cmd;

        out << fmt::format("rule {}\n", name);
        out << fmt::format("    command = {}\n", cmd);
        out << fmt::format("    description = {} $out\n", name);
    }
    out << "# feature rules\n";
    {
        YAML::Node install_feature = root["features"]["install"];
        if (install_feature.IsSequence()) {
            out << "rule install\n";
            out << "    description = install\n";
            out << "    command = install $in /usr/local/bin\n";
        }
    }
    {
        YAML::Node clean_feature = root["features"]["clean"];
        if (clean_feature.IsScalar() && clean_feature.Scalar() == "yes") {
            out << "rule clean\n";
            out << "    description = clean\n";
            out << "    command = rm -rf build\n";
        }
    }
    {
        YAML::Node reconf_feature = root["features"]["reconf"];
        if (reconf_feature.IsScalar()) {
            out << fmt::format("rule reconfigure\n");
            out << fmt::format("    description = configure\n");
            out << fmt::format("    command = {}\n", argv[0]);
        }
    }
    {
        YAML::Node run_feature = root["features"]["run"];
        if (run_feature.IsScalar()) {
            out << fmt::format("rule run\n");
            out << fmt::format("    description = run\n");
            out << fmt::format("    pool = console\n");
            out << fmt::format("    command = {}\n", run_feature.Scalar());
        }
    }

    std::vector<std::string> bdeps;

    out << "# targets\n";
    for (auto action : root["actions"]) {
        if (action.first.Scalar()[0] == '$') {
            std::vector<std::string> subdeps;
            for (auto action : action.second) {
                for (auto dep : convert(out, action.first.Scalar(), action.second)) {
                    subdeps.push_back(dep);
                }
            }
            virtrules[action.first.Scalar().substr(1)] = subdeps;
        }
    }
    for (auto action : root["actions"]) {
        if (action.first.Scalar()[0] == '$') {
            continue;
        }
        for (auto dep : convert(out, action.first.Scalar(), action.second)) {
            bdeps.push_back(dep);
        }
    }

    out << "# phony targets\n";
    nn_rule(out, "build", "phony", bdeps);
    {
        YAML::Node install_feature = root["features"]["install"];
        if (install_feature.IsSequence()) {
            out << "build install: install";
            for (auto name : install_feature) {
                out << fmt::format(" {}", name.Scalar());
            }
            out << "\n";
        }
    }
    {
        YAML::Node clean_feature = root["features"]["clean"];
        if (clean_feature.IsScalar() && clean_feature.Scalar() == "yes") {
            out << "build clean: clean\n";
        }
    }
    {
        YAML::Node reconf_feature = root["features"]["reconf"];
        if (reconf_feature.IsScalar()) {
            out << fmt::format("build {}: reconfigure\n", reconf_feature.Scalar());
        }
    }
    {
        YAML::Node run_feature = root["features"]["run"];
        if (run_feature.IsScalar()) {
            out << fmt::format("build run: run | build\n");
        }
    }
    out << "default build\n";
    // features
}