package telran.java55.security;

import org.springframework.stereotype.Component;
import lombok.RequiredArgsConstructor;
import telran.java55.post.dao.PostRepository;
import telran.java55.post.dto.exceptions.PostNotFoundException;
import telran.java55.post.model.Post;

@Component
@RequiredArgsConstructor
public class PostAuthor {
  final PostRepository postRepository;

  public boolean checkAuthor(String login, String id) {
    Post post = postRepository.findById(id).orElseThrow(PostNotFoundException::new);
    String author = post.getAuthor();
    return login.equals(author);
  }
}
