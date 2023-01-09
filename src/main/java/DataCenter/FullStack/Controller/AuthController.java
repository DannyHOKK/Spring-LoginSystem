package DataCenter.FullStack.Controller;


import DataCenter.FullStack.Model.ERole;
import DataCenter.FullStack.Model.Role;
import DataCenter.FullStack.Model.User;
import DataCenter.FullStack.Payload.Request.LoginRequest;
import DataCenter.FullStack.Payload.Request.SignupRequest;
import DataCenter.FullStack.Payload.Response.JwtResponse;
import DataCenter.FullStack.Respository.RoleRepository;
import DataCenter.FullStack.Respository.UserRepository;
import DataCenter.FullStack.Security.Jwt.JwtUtils;
import DataCenter.FullStack.Security.Service.UserDetail;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@CrossOrigin(value = "*",maxAge = 3600)
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;



    @PostMapping("/signin")
    public ResponseEntity<?> responseEntity( @RequestBody LoginRequest loginRequest){

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(),loginRequest.getPassword());

        Authentication authentication = authenticationManager.authenticate(authenticationToken);

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetail userDetails = (UserDetail) authentication.getPrincipal();
        List<String> role = userDetails.getAuthorities().stream()
                .map(roles -> roles.getAuthority()).collect(Collectors.toList());

        return ResponseEntity.ok(
                new JwtResponse(jwt,
                        userDetails.getId(),
                        userDetails.getUsername(),
                        userDetails.getEmail(),
                        role));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup (@RequestBody SignupRequest signupRequest){
        if(userRepository.existsByUsername(signupRequest.getUsername())){
            return ResponseEntity.badRequest().body("...username exists");
        }

        if(userRepository.existsByEmail(signupRequest.getEmail())){
            return ResponseEntity.badRequest().body("...email exists");
        }

        User user = new User(signupRequest.getUsername(),
                signupRequest.getEmail(),
                encoder.encode(signupRequest.getPassword()));

        Set<String> StrRoles = signupRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if(StrRoles == null){
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(()-> new RuntimeException("ERROR"));
            roles.add(userRole);

        }else{
            StrRoles.forEach(role ->{
                switch (role){
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(()-> new RuntimeException("ERROR"));
                        roles.add(adminRole);
                        break;

                    case "moderator":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(()-> new RuntimeException("ERROR"));
                        roles.add(modRole);
                        break;

                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(()-> new RuntimeException("ERROR"));
                        roles.add(userRole);

                }
            });

        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new User(user.getUsername(),
                user.getEmail(),
                user.getPassword()));

    }


}
